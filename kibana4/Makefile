# Created by: Eric Allen Griff <setjmp@hotmail.com>
# $FreeBSD$

PORTNAME=	kibana
PORTVERSION=	4.0.2
DISTVERSIONSUFFIX=	-darwin-x64
CATEGORIES=	setjmp textproc
MASTER_SITES=	http://download.elastic.co/kibana/kibana/

MAINTAINER=	setjmp@hotmail.com
COMMENT=	Kibana is a browser based dashboard for Elasticsearch

LICENSE=	APACHE20

RUN_DEPENDS=	${LOCALBASE}/bin/node:${PORTSDIR}/www/node

NO_BUILD=	yes
CONFLICTS_INSTALL=	kibana-4.1.0

do-install:
	cd ${WRKSRC}/bin && ${CP} kibana ${STAGEDIR}${LOCALBASE}/bin
	cd ${WRKSRC}/config && ${CP} kibana.yml ${STAGEDIR}${LOCALBASE}/etc/kibana.yml.sample
	${MKDIR} ${STAGEDIR}${LOCALBASE}/share/${PORTNAME}-${PORTVERSION}
	cd ${WRKSRC} && ${CP} -r src ${STAGEDIR}${LOCALBASE}/share/${PORTNAME}-${PORTVERSION}/src

.include <bsd.port.mk>
