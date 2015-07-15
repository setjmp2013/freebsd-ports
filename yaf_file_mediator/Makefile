# Created by: Eric Allen Griff <setjmp@hotmail.com>
# $FreeBSD$

PORTNAME=	yaf_file_mediator
PORTVERSION=	1.1.0
CATEGORIES=	setjmp net-mgmt
MASTER_SITES=	http://tools.netsa.cert.org/confluence/download/attachments/15958024/

MAINTAINER=	setjmp@hotmail.com
COMMENT=	YAF file mediator

LICENSE=	GPLv2

LIB_DEPENDS=	libfixbuf.so:${PORTSDIR}/setjmp/libfixbuf

GNU_CONFIGURE=	YES
INSTALL_TARGET=	install-strip
USES=		libtool pathfix pkgconfig
USE_GNOME=	glib20

PLIST_FILES=	bin/yaf_file_mediator
.include <bsd.port.mk>
