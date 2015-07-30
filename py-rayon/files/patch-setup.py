--- setup.py.orig	2015-07-30 22:18:02 UTC
+++ setup.py
@@ -101,7 +101,6 @@ dist.add_module_ext("rayon._hilbert",
 dist.add_extra_files("src/c/hilbert.h")
 
 dist.add_extra_files("pipevis/*")
-dist.add_extra_files("docmodules/*.py")
 
 # rytools and other scripts
 dist.add_script("rycategories")
