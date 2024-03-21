import datetime
import logging
import random
import string

log = logging.getLogger()


def create_csv_object(
    row_count,
    column_count,
    column_data_types,
    field_delimiter=",",
    record_delimiter="\n",
):
    csv_matrix = []
    for r_index in range(row_count):
        each_row = []
        for c_index in range(column_count):
            data_type = column_data_types[c_index]
            if data_type == "int":
                random_val = random.randint(1, 111111111111)
            if data_type == "float":
                random_val = random.uniform(111111111111111.1, 222222222222222.2)
            if data_type == "string":
                random_val = "".join(
                    random.choices(string.ascii_letters + string.digits + " ", k=20)
                )
            if data_type == "timestamp":
                current_date = datetime.datetime.now(datetime.timezone.utc)
                start_date = current_date + datetime.timedelta(days=1000)
                end_date = current_date + datetime.timedelta(days=1000)
                random_date = start_date + (end_date - start_date) * random.random()
                random_val = str(random_date.isoformat())
            each_row.append(random_val)
        csv_matrix.append(each_row)

    each_row_strings = []
    for r_index in range(row_count):
        row_string = field_delimiter.join(str(x) for x in csv_matrix[r_index])
        each_row_strings.append(row_string)
    csv_string = record_delimiter.join(each_row_strings)
    log.info(f"csv data generated: \n{csv_string}\n")
    return csv_matrix, csv_string


def execute_s3select_query(
    rgw_client,
    bucket_name,
    object_name,
    query,
    input_serialization,
    output_serialization,
):
    result = ""
    r = rgw_client.select_object_content(
        Bucket=bucket_name,
        Key=object_name,
        ExpressionType="SQL",
        InputSerialization=input_serialization,
        OutputSerialization=output_serialization,
        Expression=query,
    )

    for event in r["Payload"]:
        if "Records" in event:
            result = ""
            records = event["Records"]["Payload"].decode("utf-8")
            result += records
        if "Progress" in event:
            log.info("progress")
            log.info(event["Progress"])
        if "Stats" in event:
            log.info("Stats")
            log.info(event["Stats"])
        if "End" in event:
            log.info("End")
            log.info(event["End"])
    return result
