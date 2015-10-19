# Created by: David Thiel <lx@redundancy.redundancy.org>
# $FreeBSD: head/net/libfixbuf/Makefile 372232 2014-11-06 19:41:06Z antoine $

PORTNAME=	libfixbuf
PORTVERSION=	1.7.1
CATEGORIES=	setjmp net
MASTER_SITES=	http://tools.netsa.cert.org/releases/ \
		http://redundancy.redundancy.org/mirror/

MAINTAINER=	setjmp@hotmail.com
COMMENT=	Library for using the IP Flow Information Export protocol

LICENSE=	LGPL21

GNU_CONFIGURE=	yes
INSTALL_TARGET=	install-strip
USES=		libtool pathfix pkgconfig
USE_GNOME=	glib20
USE_LDCONFIG=	yes
USE_OPENSSL=	yes

OPTIONS_DEFINE=	SCTP OPENSSL SPREAD4

SCTP_CONFIGURE_WITH=	sctp=/usr
SPREAD4_CONFIGURE_WITH=	spread=${LOCALBASE}
OPENSSL_CONFIGURE_WITH= openssl=${OPENSSLBASE}
OPTIONS_DEFAULT=SCTP OPENSSL

.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MSPREAD4}
LIB_DEPENDS+=	libspread.so.3:${PORTSDIR}/net/spread4
.endif

.include <bsd.port.mk>
