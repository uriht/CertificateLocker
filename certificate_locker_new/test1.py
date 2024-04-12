from PIL import Image
import hashlib

md5hash = hashlib.md5(Image.open('sample/birth31.jpg').tobytes())
print(md5hash.hexdigest())
