# README

This a subdir I have going in my local /usr/ports on FreeBSD 10. My
overall goal is having these fully functional with all the option
choices I need included. When more stable, and by the full standards
of the FreeBSD ports collection, I'll submit the packages that are
not already there, and pass the ones that are in this form onto their
usual maintainers. 

*NOTE: to make all this work I had to edit /usr/ports/Mk/bsd.port.mk
and add setjmp to VALID_CATEGORIES around line 2609 to fit my local
path of /usr/ports/setjmp where this repo exists*

*NOTE: the logstash does not do file input sincedb correctly at this time
as was the case with the older one in ports without effort to. Working on
it. That is the only problem though, otherwise it functions fine.*

This is very much still a work in progress, and what's to come include:

- yaf
- silk
- logstash
- kibana4
- more to be added

**Eric**

