package main

import (
    "flag"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"log"
	"errors"
	"encoding/hex"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"hash/crc32"
	"github.com/minio/crc64nvme"
    "encoding/base64"
    "encoding/binary"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)


func main() {

    user_name := flag.String("username", "", "username of the user")
	access_key := flag.String("access", "", "access key of the user")
    secret := flag.String("secret", "", "access key of the user")
    endpoint := flag.String("endpoint", "", "endpoint url to connect to ceph rgw")
    flag.Parse()
    fmt.Printf("user_name %s\n", *user_name)
    fmt.Printf("access_key %s\n", *access_key)
    fmt.Printf("secret %s\n", *secret)
    fmt.Printf("endpoint %s\n", *endpoint)

    // Setup s3 client
	ctx := context.Background()
	s3Client := setupS3Client(ctx, *access_key, *secret, *endpoint)

    bucketName := "bucky-" + *user_name + "-1"
	createBucket(ctx, s3Client, bucketName)

	local_object_path_medium := "/home/cephuser/obj10MB"
	md5sumExpectedMedium := calculateMD5(local_object_path_medium)

	local_object_path_small := "/home/cephuser/obj9KB"
	md5sumExpectedSmall := calculateMD5(local_object_path_small)

    cksm_algo_list := []string { "sha1", "sha256", "crc32", "crc32c", "crc64nvme" }

    // Tests
    for _, algo := range cksm_algo_list {
        cksm_algo_s3_type := types.ChecksumAlgorithmSha1
        if algo == "sha1" {
            cksm_algo_s3_type = types.ChecksumAlgorithmSha1
	    }
	    if algo == "sha256" {
            cksm_algo_s3_type = types.ChecksumAlgorithmSha256
	    }
	    if algo == "crc32" {
            cksm_algo_s3_type = types.ChecksumAlgorithmCrc32
	    }
	    if algo == "crc32c" {
            cksm_algo_s3_type = types.ChecksumAlgorithmCrc32c
	    }
	    if algo == "crc64nvme" {
            cksm_algo_s3_type = types.ChecksumAlgorithmCrc64nvme
	    }

        object_size_types := []string {"small", "medium"}
        for _, object_size_type := range object_size_types {
            objectPath := local_object_path_medium
            md5sumExpected := md5sumExpectedMedium

            if object_size_type == "small"{
                objectPath = local_object_path_small
                md5sumExpected = md5sumExpectedSmall
            }

            checksum_expected := calculateChecksum(objectPath, algo)

            object_upload_types := []string {"normal", "chunked", "multipart"}
            for _, upload_type := range object_upload_types {
                if object_size_type == "small" && upload_type=="multipart"{
                    continue
                }
                objectName := "obj1" + "_" + algo + "_" + object_size_type + "_" + upload_type
                if upload_type == "normal" {
                    uploadObject(ctx, s3Client, bucketName, objectName, objectPath, cksm_algo_s3_type, checksum_expected)

                }
                if upload_type == "chunked" {
                    uploadObjectChunked(ctx, s3Client, bucketName, objectName, objectPath, cksm_algo_s3_type, checksum_expected)
                    fmt.Println()
                }
                if upload_type == "multipart" {
                    multipartUpload(ctx, s3Client, bucketName, objectName, cksm_algo_s3_type)
                    fmt.Println()
                }

                //Copy objects
                copyObjectName := objectName + "_copy"
                fmt.Println()
                CopyToBucket(ctx, s3Client, bucketName, bucketName, objectName, copyObjectName)

                //Download objects
                fmt.Println()
                DownloadFile(ctx, s3Client, bucketName, objectName, md5sumExpected)
                fmt.Println()
                DownloadFile(ctx, s3Client, bucketName, copyObjectName, md5sumExpected)

                //GetObjectAttributes
                fmt.Println()
                GetObjectAttributes(ctx, s3Client, bucketName, objectName, algo, checksum_expected, upload_type)
                fmt.Println()
                GetObjectAttributes(ctx, s3Client, bucketName, copyObjectName, algo, checksum_expected, upload_type)

                //Delete objects
                var objectIds []types.ObjectIdentifier
                objectIds = append(objectIds, types.ObjectIdentifier{Key: aws.String(objectName)})
                objectIds = append(objectIds, types.ObjectIdentifier{Key: aws.String(copyObjectName)})

                fmt.Println()
                DeleteObjects(ctx, s3Client, bucketName, objectIds, true)
            }
        }
    }
    deleteBucket(ctx, s3Client, bucketName)
}


func setupS3Client(ctx context.Context, accessKey string, secretKey string, endpointUrl string) *s3.Client {
    fmt.Println("Setting up s3 client")
// 	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithClientLogMode(aws.LogRequestWithBody|aws.LogResponseWithBody), config.WithRegion("us-east-1"), config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")) )
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithClientLogMode(aws.LogRequest|aws.LogResponse), config.WithRegion("us-east-1"), config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")) )
	if err != nil {
		fmt.Println("failed to load AWS config: %v\n", err)
		os.Exit(1)
	}

	return s3.NewFromConfig(awsConfig, func (o *s3.Options) {o.BaseEndpoint = aws.String(endpointUrl)} )
}


func createBucket(ctx context.Context, s3Client *s3.Client, bucketName string) {
	// Create a bucket
	fmt.Println("creating new bucket: ", bucketName)
	_, err := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	})
	if err != nil {
		var exists *types.BucketAlreadyExists
        if errors.As(err, &exists) {
			log.Printf("Bucket %s already exists.\n", bucketName)
			err = exists
		} else {
		        panic(err)
		    }
	}
}


func deleteBucket(ctx context.Context, s3Client *s3.Client, bucketName string) {
	// delete a bucket
	fmt.Println("deleting bucket: ", bucketName)
	_, err := s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName)})
	if err != nil {
		panic(err)
	}
}


func uploadObjectChunked(ctx context.Context, s3Client *s3.Client, bucketName string, objectName string, filePath string, cksm_algo types.ChecksumAlgorithm, checksum_expected string) {
	// Create an IO pipe. The total amount of data read isn't known to the
	// reader (S3 PutObject), so the PutObject call will use a chunked upload.
	fmt.Println("uploading chunked object ", objectName, " to bucket ", bucketName)
	pipeReader, pipeWriter := io.Pipe()
    dataToUpload, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("failed to load file: %v\n", err)
		os.Exit(1)
	}
	// Start a goroutine to write data to the pipe
	go func() {
		pipeWriter.Write(dataToUpload)
		pipeWriter.Close()
	}()

	// Upload the data from the pipe to S3 using a chunked upload
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucketName,
		Key:    &objectName,
		Body:   pipeReader,
		ChecksumAlgorithm: cksm_algo,
	})

	fmt.Printf("Uploaded chunked data to S3 bucket %s with key %s\n", bucketName, objectName)
	if err != nil {
        panic(err)
	}
}


func uploadObject(ctx context.Context, s3Client *s3.Client, bucketName string, objectName string, filePath string, cksm_algo types.ChecksumAlgorithm, checksum_expected string) {
	// Create a fixed-length byte slice to upload
	fmt.Println("uploading normal object ", objectName, " to bucket ", bucketName)
	dataToUpload, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("failed to load file: %v\n", err)
		os.Exit(1)
	}

	// Using a reader-seeker ensures that the data will be uploaded as fixed length, with the
	// content length set to the size of the byte slice.
	var readerSeeker io.ReadSeeker = bytes.NewReader(dataToUpload)

	if cksm_algo == types.ChecksumAlgorithmSha1 {
        fmt.Printf("ckcum algo is sha1\n")
	}
	if cksm_algo == types.ChecksumAlgorithmSha256 {
        fmt.Printf("ckcum algo is sha256\n")
	}
	if cksm_algo == types.ChecksumAlgorithmCrc32 {
        fmt.Printf("ckcum algo is crc32\n")
	}
	if cksm_algo == types.ChecksumAlgorithmCrc32c {
        fmt.Printf("ckcum algo is crc32c\n")
	}
	if cksm_algo == types.ChecksumAlgorithmCrc64nvme {
        fmt.Printf("ckcum algo is crc64nvme\n")
	}

	// Upload the data directly to S3
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucketName,
		Key:    &objectName,
		Body:   readerSeeker,
		ChecksumAlgorithm: cksm_algo,
	})

	fmt.Printf("Uploaded fixed-length data to S3 bucket %s with key %s\n", bucketName, objectName)
	if err != nil {
        panic(err)
	}
}


// DownloadFile gets an object from a bucket and stores it in a local file.
func DownloadFile(ctx context.Context, s3Client *s3.Client, bucketName string, objectKey string, md5sumExpected string) error {
	fmt.Println("downloading object: ", objectKey)
	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
        fmt.Printf("Couldn't get object %v:%v. Here's why: %v\n", bucketName, objectKey, err)
        fmt.Printf("Error: %v\n", err)
		panic(err)
	}
	defer result.Body.Close()
    body, err := io.ReadAll(result.Body)
	hash := md5.Sum(body)
	md5sum_actual := hex.EncodeToString(hash[:])
	fmt.Printf("md5sum actual: %s\n", md5sum_actual)
	fmt.Printf("md5sum expected: %s\n", md5sumExpected)
	if md5sum_actual != md5sumExpected {
		panic("md5sum mismatch")
	}
    return nil
}


// CopyToBucket copies an object in a bucket to another bucket.
func CopyToBucket(ctx context.Context, s3Client *s3.Client, sourceBucket string, destinationBucket string, objectKey string, copyObjectKey string) error {
	fmt.Println("copying object ", objectKey, " from source_bucket ", sourceBucket, " to destination_bucket ", destinationBucket, " with object_name ", copyObjectKey)
	_, err := s3Client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(destinationBucket),
		CopySource: aws.String(fmt.Sprintf("%v/%v", sourceBucket, objectKey)),
		Key:        aws.String(copyObjectKey),
	})
	if err != nil {
        fmt.Printf("Couldn't copy object %s from %s.\n",
            objectKey, sourceBucket)
        panic(err)
	}
    return nil
}


// DeleteObjects deletes a list of objects from a bucket.
func DeleteObjects(ctx context.Context, s3Client *s3.Client, bucket string, objects []types.ObjectIdentifier, bypassGovernance bool) error {
	fmt.Println("deleting objects from bucket ", bucket)
	if len(objects) == 0 {
		return nil
	}

	input := s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   aws.Bool(true),
		},
	}
	if bypassGovernance {
		input.BypassGovernanceRetention = aws.Bool(true)
	}
	delOut, err := s3Client.DeleteObjects(ctx, &input)
	if err != nil || len(delOut.Errors) > 0 {
		fmt.Printf("Error deleting objects from bucket %s.\n", bucket)
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}
    return nil
}


func multipartUpload(ctx context.Context, s3Client *s3.Client, bucket string, objectKey string, cksm_algo types.ChecksumAlgorithm) error {
    fmt.Println("multipart upload with object_name: ", objectKey)
    fmt.Println("creating multipart upload")
    input := &s3.CreateMultipartUploadInput{
        Bucket:      aws.String(bucket),
        Key:         aws.String(objectKey),
        ContentType: aws.String("text/plain"),
        ChecksumAlgorithm: cksm_algo,
    }
    resp, err := s3Client.CreateMultipartUpload(ctx, input)
    if err != nil {
        panic(err)
    }

    var completedParts []types.CompletedPart

    fmt.Println("uploading part1")
    part1_content, err := os.Open("/home/cephuser/obj10MB.parts/aa")
    if err != nil {
        fmt.Println("Error opening file:", err)
        panic(err)
    }
    defer part1_content.Close()
    partInput1 := &s3.UploadPartInput{
        Body:       part1_content,
        Bucket:     resp.Bucket,
        Key:        resp.Key,
        PartNumber: aws.Int32(1),
        UploadId:   resp.UploadId,
        ChecksumAlgorithm: cksm_algo,
    }
    uploadResult1, err := s3Client.UploadPart(ctx, partInput1)
    completedParts = append(completedParts, types.CompletedPart{
        ETag:       uploadResult1.ETag,
        PartNumber: aws.Int32(1),
    })

    fmt.Println("uploading part2")
    part2_content, err := os.Open("/home/cephuser/obj10MB.parts/ab")
    if err != nil {
        fmt.Println("Error opening file:", err)
        panic(err)
    }
    defer part2_content.Close()
    partInput2 := &s3.UploadPartInput{
        Body:       part2_content,
        Bucket:     resp.Bucket,
        Key:        resp.Key,
        PartNumber: aws.Int32(2),
        UploadId:   resp.UploadId,
        ChecksumAlgorithm: cksm_algo,
    }
    uploadResult2, err := s3Client.UploadPart(ctx, partInput2)
    completedParts = append(completedParts, types.CompletedPart{
        ETag:       uploadResult2.ETag,
        PartNumber: aws.Int32(2),
    })

    fmt.Println("complete multipart upload")
    compInput := &s3.CompleteMultipartUploadInput{
        Bucket:   resp.Bucket,
        Key:      resp.Key,
        UploadId: resp.UploadId,
        MultipartUpload: &types.CompletedMultipartUpload{
            Parts: completedParts,
        },
    }
    _, compErr := s3Client.CompleteMultipartUpload(ctx, compInput)
    if compErr != nil {
        panic(compErr)
    }
    //todo: comp_multi_out checksum fields verification

    return nil
}


// GetObjectAttributes returns the attributes of an object
func GetObjectAttributes(ctx context.Context, s3Client *s3.Client, bucket string, objectKey string, algo string, checksum_expected string, upload_type string) error {
    fmt.Println("performing get-object-attributes on an object: ", objectKey)
    var objectattrs []types.ObjectAttributes
    objectattrs = append(objectattrs, types.ObjectAttributesChecksum)
	result, err := s3Client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		ObjectAttributes: objectattrs,
// 		ObjectAttributes: []types.ObjectAttributes{
// 			types.ObjectAttributesChecksum,
// 			types.ObjectAttributesObjectParts,
// 			types.ObjectAttributesObjectSize,
// 			types.ObjectAttributesEtag,
// 			types.ObjectAttributesStorageClass
// 		},
	})
    if err != nil {
        panic(err)
    }
    fmt.Printf("GetObjectAttributes result for %s:\n", objectKey)
	fmt.Println(result.Checksum)
    checksum_actual := ""
    if algo == "sha1" {
        checksum_actual = *result.Checksum.ChecksumSHA1
    }
    if algo == "sha256" {
        checksum_actual = *result.Checksum.ChecksumSHA256
    }
    if algo == "crc32" {
        checksum_actual = *result.Checksum.ChecksumCRC32
    }
    if algo == "crc32c" {
        checksum_actual = *result.Checksum.ChecksumCRC32C
    }
    if algo == "crc64nvme" {
        checksum_actual = *result.Checksum.ChecksumCRC64NVME
    }
    fmt.Printf("checksum actual: %s\n", checksum_actual)
    fmt.Printf("checksum expected: %s\n", checksum_expected)
    checksum_type_actual := string(result.Checksum.ChecksumType)
    checksum_type_expected := "FULL_OBJECT"
    if algo == "sha1" || algo == "sha256"{
        if upload_type == "multipart"{
            checksum_type_expected = "COMPOSITE"
        }
    }
    fmt.Printf("checksum_type_actual: %s\n", checksum_type_actual)
    fmt.Printf("checksum_type_expected: %s\n", checksum_type_expected)

    if checksum_type_actual != checksum_type_expected{
        err_str := "Checksum not same as expected in the response. Expected " + checksum_type_expected + ", but received " + checksum_type_actual
        panic(err_str)
    } else{
            fmt.Printf("checksum_type verified successfully\n")
        }

    if checksum_actual != checksum_expected{
        if checksum_type_actual == "COMPOSITE"{
            fmt.Printf("As it is a COMPOSITE checksum, checksum is different than locally calculated entire object checksum '%s'\n", checksum_expected)
        } else{
                panic("Checksum not same as expected in the response")
            }
    }
    fmt.Printf("checksum verified successfully\n")
    return nil
}


func calculateChecksum(objectPath string, algo string) string {
    fmt.Println("calculating checksum-", algo, " on local object: ", objectPath)
	data, err := os.ReadFile(objectPath)
	if err != nil {
		fmt.Printf("failed to load local file: %v\n", err)
		os.Exit(1)
	}
	checksum := ""
    if algo == "sha1" {
        checksum_hex := sha1.Sum(data)
        checksum = base64.StdEncoding.EncodeToString(checksum_hex[:])
    }
    if algo == "sha256" {
        checksum_hex := sha256.Sum256(data)
        checksum = base64.StdEncoding.EncodeToString(checksum_hex[:])
    }
    if algo == "crc32" {
        checksum_uint_32 := crc32.ChecksumIEEE(data)
        checksumBytes := make([]byte, 4)
        binary.BigEndian.PutUint32(checksumBytes, checksum_uint_32)

        // Encode the checksum bytes to Base64
        checksum = base64.StdEncoding.EncodeToString(checksumBytes)
    }
    if algo == "crc32c" {
        crc32cTable := crc32.MakeTable(crc32.Castagnoli)
        // Calculate the CRC32C checksum.
        checksum_uint_32 := crc32.Checksum(data, crc32cTable)

        checksumBytes := make([]byte, 4)
        binary.BigEndian.PutUint32(checksumBytes, checksum_uint_32)

        // Encode the checksum bytes to Base64
        checksum = base64.StdEncoding.EncodeToString(checksumBytes)
    }
    if algo == "crc64nvme" {
        checksum_uint_64 := crc64nvme.Checksum(data)

        // Convert the uint64 checksum to a byte slice
        // This step is important because Base64 encoding works on byte slices.
        checksumBytes := make([]byte, 8)
        for i := 0; i < 8; i++ {
            checksumBytes[i] = byte(checksum_uint_64 >> (56 - i*8))
        }

        // Encode the checksum bytes to Base64
        checksum = base64.StdEncoding.EncodeToString(checksumBytes)
    }
    fmt.Printf("checksum-%s is %s\n", algo, checksum)

    return checksum
}

func calculateMD5(objectPath string) string {
    fmt.Println("calculating md5sum on local object: ", objectPath)
	data, err := os.ReadFile(objectPath)
	if err != nil {
		fmt.Printf("failed to load local file: %v\n", err)
		os.Exit(1)
	}
	hash := md5.Sum(data)
	md5sum := hex.EncodeToString(hash[:])
	fmt.Println("md5sum of local object: ", objectPath, " is: ", md5sum)
	return md5sum
}

