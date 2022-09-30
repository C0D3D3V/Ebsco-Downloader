<div align="center">
    <br>
    <h2>Ebsco Downloader</h2>
    <small>A collection of tools to download ebooks</small> 
    <br>
    <small>Built with ❤︎</small>
</div>

---

### DISCLAIMER, THIS IS ONLY FOR EDUCATIONAL PURPOSES ONLY. 
This project is to be used for educational purposes only.
I am not liable for any violation of the law that applies in your country nor for any other illegal actions or problems that may arise from the use of this project.

## 🚀 Setup

1. Install [Python](https://www.python.org/) >=3.7
2. ~~Run `pip install ebsco-dl` as administrator.~~ </br>
`ebsco-dl` is not available on pypi currently, so you have to install it by cloning this repository to your disk and run `pip install .` inside the folder that contains the `setup.py`.
4. Read the Usage section

### Usage

For an easy copy of the cookies, you can install an Add-On like `cookies.txt` [for Firefox](https://addons.mozilla.org/de/firefox/addon/cookies-txt/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search) or [for Chrome](https://chrome.google.com/webstore/detail/get-cookiestxt/bgaddhkoddajcdgocldbbfleckgcbcid). Export the cookies of your login page (`ukzn.idm.oclc.org`) to a `cookies.txt` file. 

Alternatively, you can create the `cookies.txt` file yourself, keep in mind it needs to be in Netscape format like this (`a3azaHajajaLada` is the cookie):

```
# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This is a generated file!  Do not edit.

.idm.oclc.org	TRUE	/	FALSE	2147483647	ezproxy	a3azaHajajaLada
#HttpOnly_.idm.oclc.org	TRUE	/	FALSE	2147483647	ezproxyl	a3azaHajajaLada
#HttpOnly_.idm.oclc.org	TRUE	/	TRUE	2147483647	ezproxyn	a3azaHajajaLada
```

Copy the `cookies.txt` file to the directory where you want to download the books. Open a terminal inside of that directory.

Open an ebook on your library in your browser, so you get a link that looks like this: `https://web-p-ebscohost-com.ukzn.idm.oclc.org/ehost/ebookviewer/ebook/bmxlYmtfXzI1MjQxMjhfX0FO0?sid=119ac7c8-1a4f-4b8a-8ea4-deae7f213fa4@redis&vid=0&format=EK&rid=1`


You can download this book now using this command: `ebsco-dl -dp https://web-p-ebscohost-com.ukzn.idm.oclc.org/ehost/ebookviewer/ebook/bmxlYmtfXzI1MjQxMjhfX0FO0?sid=119ac7c8-1a4f-4b8a-8ea4-deae7f213fa4@redis&vid=0&format=EK&rid=1`. The book will be downloaded in the current working directory, you can change this behavior by using the `--path` option.

If you run into certificate problems you can add `-scv` to the command, so that the certificate is not validated. 


---


## 🏆 Contributing

Do you have a great new feature idea or just want to be part of the project? Awesome! Every contribution is welcome!


## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details