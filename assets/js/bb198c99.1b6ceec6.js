"use strict";(self.webpackChunkfirezone_docs=self.webpackChunkfirezone_docs||[]).push([[3520],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>m});var n=r(7294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var l=n.createContext({}),p=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},c=function(e){var t=p(e.components);return n.createElement(l.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},y=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,a=e.originalType,l=e.parentName,c=s(e,["components","mdxType","originalType","parentName"]),u=p(r),y=o,m=u["".concat(l,".").concat(y)]||u[y]||d[y]||a;return r?n.createElement(m,i(i({ref:t},c),{},{components:r})):n.createElement(m,i({ref:t},c))}));function m(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var a=r.length,i=new Array(a);i[0]=y;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[u]="string"==typeof e?e:o,i[1]=s;for(var p=2;p<a;p++)i[p]=r[p];return n.createElement.apply(null,i)}return n.createElement.apply(null,r)}y.displayName="MDXCreateElement"},3024:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>i,default:()=>d,frontMatter:()=>a,metadata:()=>s,toc:()=>p});var n=r(7462),o=(r(7294),r(3905));const a={title:"Security Controls",sidebar_position:10},i=void 0,s={unversionedId:"reference/security-controls",id:"reference/security-controls",title:"Security Controls",description:"Firezone employs a few different security controls to keep data secure in",source:"@site/docs/reference/security-controls.mdx",sourceDirName:"reference",slug:"/reference/security-controls",permalink:"/reference/security-controls",draft:!1,editUrl:"https://github.com/firezone/firezone/tree/master/www/docs/reference/security-controls.mdx",tags:[],version:"current",sidebarPosition:10,frontMatter:{title:"Security Controls",sidebar_position:10},sidebar:"tutorialSidebar",previous:{title:"Rules",permalink:"/reference/rest-api/rules"}},l={},p=[{value:"Overview of Cryptography Used",id:"overview-of-cryptography-used",level:2},{value:"Security policy",id:"security-policy",level:2},{value:"Announcements",id:"announcements",level:3},{value:"Supported Versions",id:"supported-versions",level:3},{value:"Reporting a Vulnerability",id:"reporting-a-vulnerability",level:3},{value:"PGP Key",id:"pgp-key",level:3}],c={toc:p},u="wrapper";function d(e){let{components:t,...r}=e;return(0,o.kt)(u,(0,n.Z)({},c,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("p",null,"Firezone employs a few different security controls to keep data secure in\ntransit and at rest."),(0,o.kt)("h2",{id:"overview-of-cryptography-used"},"Overview of Cryptography Used"),(0,o.kt)("p",null,"Below is a table of cryptography used and to which contexts they apply."),(0,o.kt)("table",null,(0,o.kt)("thead",{parentName:"table"},(0,o.kt)("tr",{parentName:"thead"},(0,o.kt)("th",{parentName:"tr",align:null},"Cryptography"),(0,o.kt)("th",{parentName:"tr",align:null},"Context"),(0,o.kt)("th",{parentName:"tr",align:null},"Notes"))),(0,o.kt)("tbody",{parentName:"table"},(0,o.kt)("tr",{parentName:"tbody"},(0,o.kt)("td",{parentName:"tr",align:null},"AES-GCM"),(0,o.kt)("td",{parentName:"tr",align:null},"Data at rest"),(0,o.kt)("td",{parentName:"tr",align:null},"Used to encrypt sensitive database fields such as device preshared keys and multi-factor authentication secrets.")),(0,o.kt)("tr",{parentName:"tbody"},(0,o.kt)("td",{parentName:"tr",align:null},"Argon2"),(0,o.kt)("td",{parentName:"tr",align:null},"Data at rest"),(0,o.kt)("td",{parentName:"tr",align:null},"Used to hash user passwords for the local authentication method.")),(0,o.kt)("tr",{parentName:"tbody"},(0,o.kt)("td",{parentName:"tr",align:null},"TLSv1.2/TLSv1.3"),(0,o.kt)("td",{parentName:"tr",align:null},"Data in transit"),(0,o.kt)("td",{parentName:"tr",align:null},"Used by the Caddy server to encrypt HTTP connections to the portal. Read more at ",(0,o.kt)("a",{parentName:"td",href:"https://caddyserver.com/docs/caddyfile/directives/tls"},"https://caddyserver.com/docs/caddyfile/directives/tls"),". SSL certificates are provisioned automatically with the ACME protocol by Let's Encrypt by default.")),(0,o.kt)("tr",{parentName:"tbody"},(0,o.kt)("td",{parentName:"tr",align:null},"ChaCha20, Poly1305, Curve25519, BLAKE2s, SipHash24, HKDF"),(0,o.kt)("td",{parentName:"tr",align:null},"Data in transit"),(0,o.kt)("td",{parentName:"tr",align:null},"Used by WireGuard\xae for VPN tunnels. Read more at ",(0,o.kt)("a",{parentName:"td",href:"https://wireguard.com/protocol"},"https://wireguard.com/protocol"),". Firezone uses Linux kernel WireGuard without modification.")))),(0,o.kt)("h2",{id:"security-policy"},"Security policy"),(0,o.kt)("p",null,"We take security issues very seriously and strive to fix all security issues\nas soon as they're reported."),(0,o.kt)("h3",{id:"announcements"},"Announcements"),(0,o.kt)("p",null,"We'll announce major security issues on our security mailing list located at:"),(0,o.kt)("p",null,(0,o.kt)("a",{parentName:"p",href:"https://discourse.firez.one/?utm_source=docs.firezone.dev"},"https://discourse.firez.one/?utm_source=docs.firezone.dev")),(0,o.kt)("h3",{id:"supported-versions"},"Supported Versions"),(0,o.kt)("p",null,"We release security patches for supported versions of Firezone. We recommend\nrunning the latest version of Firezone at all times."),(0,o.kt)("h3",{id:"reporting-a-vulnerability"},"Reporting a Vulnerability"),(0,o.kt)("p",null,"Please ",(0,o.kt)("strong",{parentName:"p"},"do not")," open a Github Issue for security issues you encounter.\nInstead, please send an email to ",(0,o.kt)("inlineCode",{parentName:"p"},"security AT firezone.dev")," describing the issue\nand we'll respond as soon as possible."),(0,o.kt)("h3",{id:"pgp-key"},"PGP Key"),(0,o.kt)("p",null,"You may use the public key below to encrypt emails to ",(0,o.kt)("inlineCode",{parentName:"p"},"security AT firezone.dev"),".\nYou can also find this key at:"),(0,o.kt)("p",null,(0,o.kt)("a",{parentName:"p",href:"https://pgp.mit.edu/pks/lookup?op=get&search=0x45113BA04AD83D8A"},"https://pgp.mit.edu/pks/lookup?op=get&search=0x45113BA04AD83D8A")),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: SKS 1.1.6\nComment: Hostname: pgp.mit.edu\n\nmDMEYYwK5BYJKwYBBAHaRw8BAQdA4ooDpwDy3V0wHCftM/LHD5e713LSr0SQy49joUMgHoS0\nJkZpcmV6b25lIFNlY3VyaXR5IDxzZWN1cml0eUBmaXJlei5vbmU+iJoEExYKAEIWIQQlD4tW\ngEEHBC38anNFETugStg9igUCYYwK5AIbAwUJA8JnAAULCQgHAgMiAgEGFQoJCAsCBBYCAwEC\nHgcCF4AACgkQRRE7oErYPYoORwEAiYi3arrcR2e5OfqsoAbCN0O6M0HWeo1K/ZoFWH2jLy0B\nAMsWk58vepKqNhUKhuDb8bSjK8TOr/IxB63lSkQaz9MIuDgEYYwK5BIKKwYBBAGXVQEFAQEH\nQPLzia/me7FOsFfAJKWm0X1qC5byv2GWn6LZPV013AdoAwEIB4h+BBgWCgAmFiEEJQ+LVoBB\nBwQt/GpzRRE7oErYPYoFAmGMCuQCGwwFCQPCZwAACgkQRRE7oErYPYr0ZQEAig86wu+zrNiT\nB4t3dk3psHRj+Kdn4uURLjUBZqYNvXoA+QEBUPtP7hNjum+1FrzYmHUFdCBA/cszz7x7PQ36\n5gcE\n=0gEr\n-----END PGP PUBLIC KEY BLOCK-----\n")))}d.isMDXComponent=!0}}]);