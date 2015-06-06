# Created by: David Thiel <lx@redundancy.redundancy.org>
# $FreeBSD: head/security/silktools/Makefile 372234 2014-11-06 19:44:13Z antoine $

PORTNAME=	silktools
PORTVERSION=	3.10.2
CATEGORIES=	setjmp security net
MASTER_SITES=	http://tools.netsa.cert.org/releases/ \
		http://redundancy.redundancy.org/mirror/
DISTNAME=	silk-${PORTVERSION}

MAINTAINER=	setjmp@hotmail.com
COMMENT=	Tools for large-scale network capture analysis

LICENSE=	GPLv2

LIB_DEPENDS=	liblzo2.so:${PORTSDIR}/archivers/lzo2 \
		libfixbuf.so:${PORTSDIR}/setjmp/libfixbuf

GNU_CONFIGURE=	yes
CONFIGURE_ARGS=	--with-lzo=${LOCALBASE} --enable-packing-tools --enable-ipv6 --enable-static --enable-extra-checks
USE_LDCONFIG=	yes
USES=		gmake perl5 pkgconfig libtool
USE_PERL5=	build
INSTALL_TARGET=	install-strip

OPTIONS_DEFINE=	LOCALTIME
LOCALTIME_DESC=	Use localtime instead of UTC

LOCALTIME_CONFIGURE_ON=--enable-localtime

.include <bsd.port.mk>
