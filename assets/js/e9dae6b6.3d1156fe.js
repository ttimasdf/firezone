"use strict";(self.webpackChunkfirezone_docs=self.webpackChunkfirezone_docs||[]).push([[2895],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>g});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var l=n.createContext({}),p=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},c=function(e){var t=p(e.components);return n.createElement(l.Provider,{value:t},e.children)},d="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,o=e.originalType,l=e.parentName,c=s(e,["components","mdxType","originalType","parentName"]),d=p(r),m=a,g=d["".concat(l,".").concat(m)]||d[m]||u[m]||o;return r?n.createElement(g,i(i({ref:t},c),{},{components:r})):n.createElement(g,i({ref:t},c))}));function g(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=r.length,i=new Array(o);i[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[d]="string"==typeof e?e:a,i[1]=s;for(var p=2;p<o;p++)i[p]=r[p];return n.createElement.apply(null,i)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},9791:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>i,default:()=>k,frontMatter:()=>o,metadata:()=>s,toc:()=>p});var n=r(7462),a=(r(7294),r(3905));const o={title:"Regenerate Secret Keys",sidebar_position:7},i=void 0,s={unversionedId:"administer/regen-keys",id:"administer/regen-keys",title:"Regenerate Secret Keys",description:"When you install Firezone, secrets are generated for encrypting database",source:"@site/docs/administer/regen-keys.mdx",sourceDirName:"administer",slug:"/administer/regen-keys",permalink:"/administer/regen-keys",draft:!1,editUrl:"https://github.com/firezone/firezone/tree/master/www/docs/administer/regen-keys.mdx",tags:[],version:"current",sidebarPosition:7,frontMatter:{title:"Regenerate Secret Keys",sidebar_position:7},sidebar:"tutorialSidebar",previous:{title:"Troubleshoot",permalink:"/administer/troubleshoot"},next:{title:"Debug Logs",permalink:"/administer/debug-logs"}},l={},p=[{value:"Regenerate secrets",id:"regenerate-secrets",level:2},{value:"Regenerate WireGuard private key",id:"regenerate-wireguard-private-key",level:2}],c=e=>function(t){return console.warn("Component "+e+" was not imported, exported, or provided by MDXProvider as global scope"),(0,a.kt)("div",t)},d=c("Tabs"),u=c("TabItem"),m={toc:p},g="wrapper";function k(e){let{components:t,...r}=e;return(0,a.kt)(g,(0,n.Z)({},m,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("p",null,"When you install Firezone, secrets are generated for encrypting database\nfields, securing WireGuard tunnels, securing cookie sessions, and more."),(0,a.kt)("p",null,"If you're looking to regenerate one or more of these secrets, it's possible\nto do so using the same bootstrap scripts that were used when installing\nFirezone."),(0,a.kt)("h2",{id:"regenerate-secrets"},"Regenerate secrets"),(0,a.kt)("admonition",{type:"warning"},(0,a.kt)("p",{parentName:"admonition"},"Replacing the ",(0,a.kt)("inlineCode",{parentName:"p"},"DATABASE_ENCRYPTION_KEY")," will render all encrypted data in the\ndatabase useless. This ",(0,a.kt)("strong",{parentName:"p"},"will")," break your Firezone install unless you are\nstarting with an empty database. You have been warned.")),(0,a.kt)("admonition",{type:"caution"},(0,a.kt)("p",{parentName:"admonition"},"Replacing ",(0,a.kt)("inlineCode",{parentName:"p"},"GUARDIAN_SECRET_KEY"),", ",(0,a.kt)("inlineCode",{parentName:"p"},"SECRET_KEY_BASE"),", ",(0,a.kt)("inlineCode",{parentName:"p"},"LIVE_VIEW_SIGNING_SALT"),",\n",(0,a.kt)("inlineCode",{parentName:"p"},"COOKIE_SIGNING_SALT"),", and ",(0,a.kt)("inlineCode",{parentName:"p"},"COOKIE_ENCRYPTION_SALT")," will reset all browser\nsessions and REST API tokens.")),(0,a.kt)("p",null,"Use the procedure below to regenerate secrets:"),(0,a.kt)(d,{mdxType:"Tabs"},(0,a.kt)(u,{value:"docker",label:"Docker",default:!0,mdxType:"TabItem"},(0,a.kt)("p",null,"Navigate to the Firezone installation directory, then:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"mv .env .env.bak\ndocker run firezone/firezone bin/gen-env > .env\n")),(0,a.kt)("p",null,"Now, move desired env vars from ",(0,a.kt)("inlineCode",{parentName:"p"},".env.bak")," back to ",(0,a.kt)("inlineCode",{parentName:"p"},".env"),", keeping\nthe new secrets intact.")),(0,a.kt)(u,{value:"omnibus",label:"Omnibus",mdxType:"TabItem"},(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"mv /etc/firezone/secrets.json /etc/firezone/secrets.bak.json\nsudo firezone-ctl reconfigure\n")))),(0,a.kt)("h2",{id:"regenerate-wireguard-private-key"},"Regenerate WireGuard private key"),(0,a.kt)("admonition",{type:"warning"},(0,a.kt)("p",{parentName:"admonition"},"Replacing the WireGuard private key will render all existing device configs\ninvalid. Only do so if you're prepared to also regenerate device configs\nafter regenerating the WireGuard private key.")),(0,a.kt)("p",null,"To regenerate WireGuard private key, simply move or rename the private key file.\nFirezone will generate a new one on next start."),(0,a.kt)(d,{mdxType:"Tabs"},(0,a.kt)(u,{value:"docker",label:"Docker",default:!0,mdxType:"TabItem"},(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"cd $HOME/.firezone\ndocker-compose stop firezone\nsudo mv firezone/private_key firezone/private_key.bak\ndocker-compose start firezone\n"))),(0,a.kt)(u,{value:"omnibus",label:"Omnibus",mdxType:"TabItem"},(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"sudo firezone-ctl stop phoenix\nsudo mv /var/opt/firezone/cache/wg_private_key /var/opt/firezone/cache/wg_private_key.bak\nsudo firezone-ctl start phoenix\n")))))}k.isMDXComponent=!0}}]);