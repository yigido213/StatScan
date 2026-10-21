import os, shutil, json, datetime, requests

def yedekle(src, dst):
    ad = datetime.datetime.now().strftime('%Y%m%d')
    shutil.copytree(src, os.path.join(dst, ad))

def surum():
    r = requests.get('https://api.github.com/repos/python/cpython/releases/latest', timeout=10)
    return r.json()['tag_name']

if __name__ == '__main__':
    yedekle('belgeler', 'yedek')
    print(surum())
