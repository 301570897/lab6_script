import os
import base64
import exifread                                                                                                 # type: ignore
from PIL import Image                                                                                           # type: ignore
from PIL.ExifTags import TAGS, GPSTAGS                                                                          # type: ignore
from datetime import datetime

def decode_base64(value):
    try:
        decoded = base64.b64decode(value).decode("utf-8")
        if decoded.isprintable():
            return decoded
    except:
        pass

table = []
secrets = []
img_secrets = {}
# iterate over all images
image_folder = os.path.expanduser("~/Desktop/images")
for img in os.listdir(image_folder):
    if not img.lower().endswith((".jpg", ".jpeg", ".png")):
        continue
    image_path = os.path.join(image_folder, img)
    print("Image:", img)
    risk_score = 0
    img_secret = None
    found_secrets = []
    
    #metadata extraction
    with open(image_path, 'rb') as f:
        tags = exifread.process_file(f, details=False)

    if not tags:
        print("No EXIF metadata")

    #covert channels detection
    covert_found = False
    for tag in tags:
        if any(keyword in tag for keyword in ["UserComment", "ImageDescription",  "Camera model", "Software", "Software", "Copyright"]):
            covert_found = True
    if covert_found:
        print("Covert Channel Detection | Unusual metadata detected")
        fields = {
            "Camera make": tags.get("Image Make"), 
            "Camera model": tags.get("Image Model"), 
            "Software": tags.get("Image Software"), 
            "UserComment": tags.get("EXIF UserComment"),
            "ImageDescription": tags.get("Image ImageDescription"),
            "Copyright": tags.get("Image Copyright")
            }
        
        for name, value in fields.items():
            if value:
                decoded = decode_base64(str(value).encode())
                if decoded:
                    found_secrets.append(decoded)
                    print(f"Decoded {name}: {decoded}")
                else:
                    if name in ["UserComment", "ImageDescription", "Camera make", "Camera model", "Software", "Copyright"]:
                        if str(value).lower() not in ["none"]:
                            found_secrets.append(str(value))
                            print(f"{name}: {str(value)}")
        risk_score += 10
    if found_secrets:
        img_secret = "".join(dict.fromkeys(found_secrets))
        print(f"Secrets found: {img_secret}")
        secrets.append(img_secret)
    else:
        print("No Covert Channels detected")

    #consistency check| anomalous timestamps
    if "EXIF DateTimeOriginal" in tags:
        exif_time = datetime.strptime(str(tags["EXIF DateTimeOriginal"]), "%Y:%m:%d %H:%M:%S")
        fs_modified = datetime.fromtimestamp(os.stat(image_path).st_mtime)
        print("DateTimeOrigianl:", tags["EXIF DateTimeOriginal"])
        print("EXIF time:", exif_time)
        print("Modified time:", fs_modified)
        if exif_time != fs_modified:
            print("Anomaly detection | Timestamp inconcsistency")
            risk_score += 5
        else:
            print("No anomaly detected.")
    else:
        print("No EXIF timestamp")

    #editing software detection
    if "Image Software" in tags:
        print("Image editing software detected")
        risk_score += 5
        print("Software:", tags.get("Image Software"))
    else:
        print("No editing software detected.")

    # gps coordinates detection
    image = Image.open(image_path)
    gps_found = False
    if hasattr(image, "_getexif") and image._getexif():
        for tag_id, value in image._getexif().items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name == "GPSInfo":
                print("Privacy Leak | GPS coordinates present")
                risk_score += 5
                for gps_id in value:
                    gps_name = GPSTAGS.get(gps_id, gps_id)
                    print("GPS", gps_name, ":", value[gps_id])
    else:
        print("No GPS data found.")

    table.append([img, risk_score, img_secret if img_secret else "None"])
    
    #print risk score
    print("Risk Score:", risk_score)
    print("-------------------------")

print("\nFull Secret:")
if secrets:
    print("\n".join(secrets))
 
print("="*100)   
print("TABLE ")
print("="*100)
print(f"{'Image Name':<20} | {'Risk Score':<10} | {'Secrets'}")
for row in table:
    print(f"{row[0]:<20} | {row[1]:<10} | {row[2]}")
print("="*100)
