# Created by: Eric Allen Griff <setjmp@hotmail.com>
# $FreeBSD$

PORTNAME=	libp0f
PORTVERSION=	2.0.8
PORTREVISION=	2
CATEGORIES=	net
MASTER_SITES=	http://tools.netsa.cert.org/releases/
DISTFILES=	libp0f-2.0.8-2012032901.tar.xz
DISTNAME=	libp0f-2.0.8-2012032901
MAINTAINER=	setjmp@hotmail.com
COMMENT=	Library of p0f-2.x for yaf as in the CERT NETSA confluence

LICENSE=	LGPL21

GNU_CONFIGURE=	YES
CONFIGURE_ARGS=	--sysconfdir=${LOCALBASE}/etc
INSTALL_TARGET=	install-strip
USES=		libtool pathfix pkgconfig tar:tgz

post-stage:
	${RM} -f ${STAGEDIR}${LOCALBASE}/bin/p0f
	${MV} ${STAGEDIR}/etc/p0f ${STAGEDIR}${LOCALBASE}/etc/libp0f
	${RM} -rf ${STAGEDIR}/etc

.include <bsd.port.mk>
