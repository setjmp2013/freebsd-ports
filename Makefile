# $FreeBSD: head/net/Makefile 387990 2015-05-30 23:07:42Z sunpoet $
#

    COMMENT = setjmp local ports

    SUBDIR += libp0f
    SUBDIR += logstash
    SUBDIR += libfixbuf
    SUBDIR += yaf
    SUBDIR += yaf-file-mediator
    SUBDIR += py-elasticsearch-py

.include <bsd.port.subdir.mk>
