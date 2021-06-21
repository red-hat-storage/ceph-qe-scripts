import urllib


def download_image():

    image_loc = "http://download.cirros-cloud.net/0.3.4/cirros-0.3.4-x86_64-disk.img"
    download_loc = "/tmp/image.img"
    urllib.urlretrieve(image_loc, download_loc)
    return download_loc
