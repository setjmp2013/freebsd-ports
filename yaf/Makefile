# Created by: Dikshie <dikshie@sfc.wide.ad.jp>
# $FreeBSD: head/net-mgmt/yaf/Makefile 372233 2014-11-06 19:42:23Z antoine $

PORTNAME=	yaf
PORTVERSION=	2.8.1
CATEGORIES=	setjmp net-mgmt
MASTER_SITES=	http://tools.netsa.cert.org/releases/

MAINTAINER=	setjmp@hotmail.com
COMMENT=	YAF is Yet Another Flowmeter

LICENSE=	GPLv2
LICENSE_FILE=	${WRKSRC}/COPYING

LIB_DEPENDS=	libfixbuf.so:${PORTSDIR}/setjmp/libfixbuf \
		libltdl.so:${PORTSDIR}/devel/libltdl \
		libpcre.so:${PORTSDIR}/devel/pcre \
		libp0f.so:${PORTSDIR}/setjmp/libp0f

GNU_CONFIGURE=	yes
INSTALL_TARGET=	install-strip
USES=		libtool pathfix perl5 pkgconfig
USE_GNOME=	glib20
USE_LDCONFIG=	yes
CONFIGURE_ARGS=	--disable-doxygen-doc --enable-applabel --enable-plugins --enable-p0fprinter --enable-fpexporter --enable-entropy --enable-mpls --enable-nonip

PLIST_SUB+=	PORTVERSION="${PORTVERSION}"

.if defined(WITH_DAG)
CONFIGURE_ARGS+=	--with-dag=${LOCALBASE}
.endif

post-stage:
	${RM} ${STAGEDIR}${LOCALBASE}/etc/p0f.fp

post-install:
.for f in dhcp_fingerprints.conf yafApplabelRules.conf yafDPIRules.conf
	${MV} ${STAGEDIR}${PREFIX}/etc/$f ${STAGEDIR}${PREFIX}/etc/$f.sample
.endfor

.include <bsd.port.mk>
