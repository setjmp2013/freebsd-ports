# Created by: Eric Allen Griff <setjmp@hotmail.com>
# $FreeBSD$

PORTNAME=	libp0f
PORTVERSION=	2.0.8
CATEGORIES=	setjmp net
MASTER_SITES=	http://tools.netsa.cert.org/confluence/download/attachments/16547842/
DISTNAME=	p0flib

MAINTAINER=	setjmp@hotmail.com
COMMENT=	Library of p0f for yaf

LICENSE=	LGPL21

WRKSRC_SUBDIR=	libp0f
GNU_CONFIGURE=	YES
CONFIGURE_ARGS=	--sysconfdir=${LOCALBASE}/etc
INSTALL_TARGET=	install-strip
USES=		tar:tgz libtool pathfix pkgconfig

post-stage:
	${MV} ${STAGEDIR}/etc/p0f ${STAGEDIR}/usr/local/etc/libp0f
	${RMDIR} ${STAGEDIR}/etc

.include <bsd.port.mk>
