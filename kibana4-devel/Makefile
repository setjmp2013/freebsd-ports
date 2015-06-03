# Created by: Eric Allen Griff <setjmp@hotmail.com>
# $FreeBSD$

PORTNAME=	kibana
PORTVERSION=	4.1.0
DISTVERSIONSUFFIX=	-snapshot-darwin-x64
CATEGORIES=	setjmp
MASTER_SITES=	http://download.elastic.co/kibana/kibana/

MAINTAINER=	setjmp@hotmail.com
COMMENT=	Kibana

LICENSE=	APACHE20

NO_BUILD=	yes

do-install:
	#cd ${WORKSRC}/bin && ${COPYTREE_SHARE} . ${STAGEDIR}/bin
	cd ${WRKSRC}/bin && ${CP} kibana ${STAGEDIR}${LOCALBASE}/bin
	cd ${WRKSRC}/config && ${CP} kibana.yml ${STAGEDIR}${LOCALBASE}/etc/kibana.yml.sample
	echo ${PORTNAME}-${PORTVERSION}
	${MKDIR} ${STAGEDIR}${LOCALBASE}/share/${PORTNAME}-${PORTVERSION}
	cd ${WRKSRC} && ${CP} -r src ${STAGEDIR}${LOCALBASE}/share/${PORTNAME}-${PORTVERSION}/src

.include <bsd.port.mk>
