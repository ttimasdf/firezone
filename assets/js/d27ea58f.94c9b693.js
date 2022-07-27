"use strict";(self.webpackChunknew_docs=self.webpackChunknew_docs||[]).push([[4449],{3905:function(e,t,n){n.d(t,{Zo:function(){return p},kt:function(){return u}});var r=n(7294);function o(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function a(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?a(Object(n),!0).forEach((function(t){o(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):a(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,o=function(e,t){if(null==e)return{};var n,r,o={},a=Object.keys(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||(o[n]=e[n]);return o}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var s=r.createContext({}),c=function(e){var t=r.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},p=function(e){var t=c(e.components);return r.createElement(s.Provider,{value:t},e.children)},m={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,o=e.mdxType,a=e.originalType,s=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),d=c(n),u=o,f=d["".concat(s,".").concat(u)]||d[u]||m[u]||a;return n?r.createElement(f,i(i({ref:t},p),{},{components:n})):r.createElement(f,i({ref:t},p))}));function u(e,t){var n=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var a=n.length,i=new Array(a);i[0]=d;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:o,i[1]=l;for(var c=2;c<a;c++)i[c]=n[c];return r.createElement.apply(null,i)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},9278:function(e,t,n){n.r(t),n.d(t,{assets:function(){return p},contentTitle:function(){return s},default:function(){return u},frontMatter:function(){return l},metadata:function(){return c},toc:function(){return m}});var r=n(7462),o=n(3366),a=(n(7294),n(3905)),i=["components"],l={title:"Telemetry",sidebar_position:4},s=void 0,c={unversionedId:"reference/telemetry",id:"reference/telemetry",title:"Telemetry",description:"This document presents an overview of the telemetry Firezone collects from your",source:"@site/docs/reference/telemetry.md",sourceDirName:"reference",slug:"/reference/telemetry",permalink:"/reference/telemetry",draft:!1,editUrl:"https://github.com/firezone/firezone/docs/reference/telemetry.md",tags:[],version:"current",sidebarPosition:4,frontMatter:{title:"Telemetry",sidebar_position:4},sidebar:"tutorialSidebar",previous:{title:"nftables Firewall Template",permalink:"/reference/firewall-templates/nftables"}},p={},m=[{value:"Why Firezone collects telemetry",id:"why-firezone-collects-telemetry",level:2},{value:"How we collect telemetry",id:"how-we-collect-telemetry",level:2},{value:"How to disable telemetry",id:"how-to-disable-telemetry",level:2}],d={toc:m};function u(e){var t=e.components,n=(0,o.Z)(e,i);return(0,a.kt)("wrapper",(0,r.Z)({},d,n,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("p",null,"This document presents an overview of the telemetry Firezone collects from your\nself-hosted instance and how to disable it."),(0,a.kt)("h2",{id:"why-firezone-collects-telemetry"},"Why Firezone collects telemetry"),(0,a.kt)("p",null,"We ",(0,a.kt)("em",{parentName:"p"},"rely")," on telemetry to prioritize our roadmap and optimize the engineering\nresources we have to make Firezone better for everyone."),(0,a.kt)("p",null,"The telemetry we collect aims to answer the following questions:"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},"How many people install, use, and stop using Firezone?"),(0,a.kt)("li",{parentName:"ul"},"What features are most valuable, and which ones don\u2019t see any use?"),(0,a.kt)("li",{parentName:"ul"},"What functionality needs the most improvement?"),(0,a.kt)("li",{parentName:"ul"},"When something breaks, why did it break, and how can we prevent it from happening\nin the future?")),(0,a.kt)("h2",{id:"how-we-collect-telemetry"},"How we collect telemetry"),(0,a.kt)("p",null,"There are three main places where telemetry is collected in Firezone:"),(0,a.kt)("ol",null,(0,a.kt)("li",{parentName:"ol"},"Package telemetry. Includes events such as install, uninstall, and upgrade."),(0,a.kt)("li",{parentName:"ol"},"CLI telemetry from ",(0,a.kt)("inlineCode",{parentName:"li"},"firezone-ctl")," commands."),(0,a.kt)("li",{parentName:"ol"},"Product telemetry associated with the Web portal.")),(0,a.kt)("p",null,"In each of these three contexts, we capture the minimum amount of data necessary\nto answer the questions in the section above."),(0,a.kt)("p",null,"Admin emails are collected ",(0,a.kt)("strong",{parentName:"p"},"only if")," you explicitly opt-in to product updates.\nOtherwise, personally-identifiable information is ",(0,a.kt)("strong",{parentName:"p"},(0,a.kt)("em",{parentName:"strong"},"never"))," collected."),(0,a.kt)("p",null,"We store telemetry in a self-hosted instance of PostHog running in a private\nKubernetes cluster, only accessible by the Firezone team. Here is an example of\na telemetry event that is sent from your instance of Firezone to our telemetry server:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-json"},'{\n    "id": "0182272d-0b88-0000-d419-7b9a413713f1",\n    "timestamp": "2022-07-22T18:30:39.748000+00:00",\n    "event": "fz_http_started",\n    "distinct_id": "1ec2e794-1c3e-43fc-a78f-1db6d1a37f54",\n    "properties": {\n        "$geoip_city_name": "Ashburn",\n        "$geoip_continent_code": "NA",\n        "$geoip_continent_name": "North America",\n        "$geoip_country_code": "US",\n        "$geoip_country_name": "United States",\n        "$geoip_latitude": 39.0469,\n        "$geoip_longitude": -77.4903,\n        "$geoip_postal_code": "20149",\n        "$geoip_subdivision_1_code": "VA",\n        "$geoip_subdivision_1_name": "Virginia",\n        "$geoip_time_zone": "America/New_York",\n        "$ip": "52.200.241.107",\n        "$plugins_deferred": [],\n        "$plugins_failed": [],\n        "$plugins_succeeded": [\n            "GeoIP (3)"\n        ],\n        "distinct_id": "1zc2e794-1c3e-43fc-a78f-1db6d1a37f54",\n        "fqdn": "awsdemo.firezone.dev",\n        "kernel_version": "linux 5.13.0",\n        "version": "0.4.6"\n    },\n    "elements_chain": ""\n}\n')),(0,a.kt)("h2",{id:"how-to-disable-telemetry"},"How to disable telemetry"),(0,a.kt)("div",{className:"admonition admonition-note alert alert--secondary"},(0,a.kt)("div",{parentName:"div",className:"admonition-heading"},(0,a.kt)("h5",{parentName:"div"},(0,a.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,a.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"14",height:"16",viewBox:"0 0 14 16"},(0,a.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M6.3 5.69a.942.942 0 0 1-.28-.7c0-.28.09-.52.28-.7.19-.18.42-.28.7-.28.28 0 .52.09.7.28.18.19.28.42.28.7 0 .28-.09.52-.28.7a1 1 0 0 1-.7.3c-.28 0-.52-.11-.7-.3zM8 7.99c-.02-.25-.11-.48-.31-.69-.2-.19-.42-.3-.69-.31H6c-.27.02-.48.13-.69.31-.2.2-.3.44-.31.69h1v3c.02.27.11.5.31.69.2.2.42.31.69.31h1c.27 0 .48-.11.69-.31.2-.19.3-.42.31-.69H8V7.98v.01zM7 2.3c-3.14 0-5.7 2.54-5.7 5.68 0 3.14 2.56 5.7 5.7 5.7s5.7-2.55 5.7-5.7c0-3.15-2.56-5.69-5.7-5.69v.01zM7 .98c3.86 0 7 3.14 7 7s-3.14 7-7 7-7-3.12-7-7 3.14-7 7-7z"}))),"note")),(0,a.kt)("div",{parentName:"div",className:"admonition-content"},(0,a.kt)("p",{parentName:"div"},"We ",(0,a.kt)("em",{parentName:"p"},"rely")," on product analytics to make Firezone better for everyone.\nLeaving telemetry enabled is the ",(0,a.kt)("strong",{parentName:"p"},"single most valuable contribution")," you can\nmake to Firezone\u2019s development. That said, we understand some users have higher\nprivacy or security requirements and would prefer to disable telemetry altogether.\nIf that\u2019s you, keep reading."))),(0,a.kt)("p",null,"Telemetry is enabled by default. To completely disable product telemetry, set the\nfollowing configuration option to ",(0,a.kt)("inlineCode",{parentName:"p"},"false")," in ",(0,a.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")," and run\n",(0,a.kt)("inlineCode",{parentName:"p"},"sudo firezone-ctl reconfigure")," to pick up the changes."),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-ruby"},"default['firezone']['telemetry']['enabled'] = false\n")),(0,a.kt)("p",null,"That will completely disable all product telemetry."),(0,a.kt)("div",{className:"admonition admonition-note alert alert--secondary"},(0,a.kt)("div",{parentName:"div",className:"admonition-heading"},(0,a.kt)("h5",{parentName:"div"},(0,a.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,a.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"14",height:"16",viewBox:"0 0 14 16"},(0,a.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M6.3 5.69a.942.942 0 0 1-.28-.7c0-.28.09-.52.28-.7.19-.18.42-.28.7-.28.28 0 .52.09.7.28.18.19.28.42.28.7 0 .28-.09.52-.28.7a1 1 0 0 1-.7.3c-.28 0-.52-.11-.7-.3zM8 7.99c-.02-.25-.11-.48-.31-.69-.2-.19-.42-.3-.69-.31H6c-.27.02-.48.13-.69.31-.2.2-.3.44-.31.69h1v3c.02.27.11.5.31.69.2.2.42.31.69.31h1c.27 0 .48-.11.69-.31.2-.19.3-.42.31-.69H8V7.98v.01zM7 2.3c-3.14 0-5.7 2.54-5.7 5.68 0 3.14 2.56 5.7 5.7 5.7s5.7-2.55 5.7-5.7c0-3.15-2.56-5.69-5.7-5.69v.01zM7 .98c3.86 0 7 3.14 7 7s-3.14 7-7 7-7-3.12-7-7 3.14-7 7-7z"}))),"note")),(0,a.kt)("div",{parentName:"div",className:"admonition-content"},(0,a.kt)("p",{parentName:"div"},"If you\u2019re looking for support running Firezone in air-gapped or other restrictive\nenvironments, ",(0,a.kt)("a",{parentName:"p",href:"mailto:sales@firezone.dev"},"contact us")," about our\n",(0,a.kt)("a",{parentName:"p",href:"https://www.firezone.dev/pricing"},"Enterprise"),"\xa0functionality."))))}u.isMDXComponent=!0}}]);