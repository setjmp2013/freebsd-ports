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

This is very much still a work in progress, and what's to come include:

- yaf
- silk
- kibana4 - not submitted as there is another capable that was ahead of me to.
- super_mediator
- yaf_file_mediator
- libp0f
- more to be added

# Submitted
- libp0f
- yaf_file_mediator

# Emailed port maintainer
- libfixbuf

**Eric**

