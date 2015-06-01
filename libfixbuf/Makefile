# Created by: David Thiel <lx@redundancy.redundancy.org>
# $FreeBSD: head/net/libfixbuf/Makefile 372232 2014-11-06 19:41:06Z antoine $

PORTNAME=	libfixbuf
PORTVERSION=	1.6.2
CATEGORIES=	net
MASTER_SITES=	http://tools.netsa.cert.org/releases/ \
		http://redundancy.redundancy.org/mirror/

MAINTAINER=	setjmp@hotmail.com
COMMENT=	Library for using the IP Flow Information Export protocol

LICENSE=	LGPL21

GNU_CONFIGURE=	yes
CONFIGURE_ARGS= --with-openssl=/usr --with-spread=${LOCALBASE}
INSTALL_TARGET=	install-strip
USES=		libtool pathfix pkgconfig
USE_GNOME=	glib20
USE_LDCONFIG=	yes

.include <bsd.port.mk>
