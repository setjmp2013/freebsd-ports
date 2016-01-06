# Created by: Eric Allen Griff <setjmp@hotmail.com>
# $FreeBSD$

PORTNAME=	super_mediator
PORTVERSION=	1.2.1
CATEGORIES=	setjmp net-mgmt
MASTER_SITES=	http://tools.netsa.cert.org/releases/

MAINTAINER=	setjmp@hotmail.com
COMMENT=	NETSA super_mediator

LICENSE=	GPLv2

LIB_DEPENDS=	libfixbuf.so:${PORTSDIR}/setjmp/libfixbuf libsilk.so:${PORTSDIR}/setjmp/silktools

GNU_CONFIGURE=	YES
INSTALL_TARGET=	install-strip
USES=		libtool pathfix pkgconfig
USE_GNOME=	glib20

OPTIONS_DEFINE=	MYSQL SPREAD4 SILKIPSET
OPTIONS_SUB=	yes
.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MSPREAD4}
LIB_DEPENDS+=	libspread.so.3:${PORTSDIR}/net/spread4
CONFITURE_ARGS+=	--with-spread=${LOCALBASE}
.else
CONFIGURE_ARGS+=	--with-spread=no
.endif

.if ${PORT_OPTIONS:MMYSQL}
USE_MYSQL=	client
CONFIGURE_ARGS+=	--with-mysql=yes
.else
CONFIGURE_ARGS+=	--with-mysql=no
.endif

.if ${PORT_OPTIONS:MSILKIPSET}
CONFIGURE_ARGS+=	--with-skipset=${LOCALBASE}
LIB_DEPENDS+=	libsilk.so:${PORTSDIR}/setjmp/silktools
.else
CONFIGURE_ARGS+=	--without-skipset
.endif

.include <bsd.port.mk>
