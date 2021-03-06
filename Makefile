# $FreeBSD: head/net/Makefile 387990 2015-05-30 23:07:42Z sunpoet $
#

    COMMENT = setjmp local ports

    SUBDIR += libp0f
    SUBDIR += libfixbuf
    SUBDIR += yaf
    SUBDIR += yaf_file_mediator
    SUBDIR += py-elasticsearch-py
    SUBDIR += silktools
    SUBDIR += IPAsuite
    SUBDIR += py-netsa
    SUBDIR += kibana4
    SUBDIR += kibana4-devel
    SUBDIR += analysis-pipeline
    SUBDIR += super_mediator
    SUBDIR += orcus
    SUBDIR += py-rayon

.include <bsd.port.subdir.mk>
