"use strict";(self.webpackChunkfirezone_docs=self.webpackChunkfirezone_docs||[]).push([[9009],{3905:(e,t,n)=>{n.d(t,{Zo:()=>d,kt:()=>g});var a=n(7294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},i=Object.keys(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var s=a.createContext({}),p=function(e){var t=a.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},d=function(e){var t=p(e.components);return a.createElement(s.Provider,{value:t},e.children)},u="mdxType",c={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},m=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,i=e.originalType,s=e.parentName,d=l(e,["components","mdxType","originalType","parentName"]),u=p(n),m=r,g=u["".concat(s,".").concat(m)]||u[m]||c[m]||i;return n?a.createElement(g,o(o({ref:t},d),{},{components:n})):a.createElement(g,o({ref:t},d))}));function g(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=n.length,o=new Array(i);o[0]=m;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[u]="string"==typeof e?e:r,o[1]=l;for(var p=2;p<i;p++)o[p]=n[p];return a.createElement.apply(null,o)}return a.createElement.apply(null,n)}m.displayName="MDXCreateElement"},6008:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>c,frontMatter:()=>i,metadata:()=>l,toc:()=>p});var a=n(7462),r=(n(7294),n(3905));const i={title:"OneLogin",sidebar_position:3,description:"Enforce 2FA/MFA using Onelogin for users of Firezone's WireGuard\xae-based secure access platform. This guide walks through integrating OneLogin for single sign-on using the SAML 2.0 connector."},o="Enable SSO with OneLogin (SAML 2.0)",l={unversionedId:"authenticate/saml/onelogin",id:"authenticate/saml/onelogin",title:"OneLogin",description:"Enforce 2FA/MFA using Onelogin for users of Firezone's WireGuard\xae-based secure access platform. This guide walks through integrating OneLogin for single sign-on using the SAML 2.0 connector.",source:"@site/docs/authenticate/saml/onelogin.mdx",sourceDirName:"authenticate/saml",slug:"/authenticate/saml/onelogin",permalink:"/authenticate/saml/onelogin",draft:!1,editUrl:"https://github.com/firezone/firezone/tree/master/www/docs/authenticate/saml/onelogin.mdx",tags:[],version:"current",sidebarPosition:3,frontMatter:{title:"OneLogin",sidebar_position:3,description:"Enforce 2FA/MFA using Onelogin for users of Firezone's WireGuard\xae-based secure access platform. This guide walks through integrating OneLogin for single sign-on using the SAML 2.0 connector."},sidebar:"tutorialSidebar",previous:{title:"Google Workspace",permalink:"/authenticate/saml/google"},next:{title:"JumpCloud",permalink:"/authenticate/saml/jumpcloud"}},s={},p=[{value:"Step 1: Create a SAML connector",id:"step-1-create-a-saml-connector",level:2},{value:"Step 2: Add SAML identity provider to Firezone",id:"step-2-add-saml-identity-provider-to-firezone",level:2}],d={toc:p},u="wrapper";function c(e){let{components:t,...n}=e;return(0,r.kt)(u,(0,a.Z)({},d,n,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"enable-sso-with-onelogin-saml-20"},"Enable SSO with OneLogin (SAML 2.0)"),(0,r.kt)("admonition",{type:"note"},(0,r.kt)("p",{parentName:"admonition"},"This guide assumes you have completed the prerequisite steps\n(e.g. generate self-signed X.509 certificates) outlined ",(0,r.kt)("a",{parentName:"p",href:"/authenticate/saml#prerequisites"},"here"),".")),(0,r.kt)("p",null,"Firezone supports Single Sign-On (SSO) using OneLogin through the generic SAML 2.0 connector.\nThis guide will walk you through how to configure the integration."),(0,r.kt)("h2",{id:"step-1-create-a-saml-connector"},"Step 1: Create a SAML connector"),(0,r.kt)("p",null,"In the OneLogin admin portal, add an app under the application tab.\nSelect ",(0,r.kt)("inlineCode",{parentName:"p"},"SAML Custom Connector (Advanced)")," and provide the appropriate\nconfiguration settings under the under the configuration tab."),(0,r.kt)("p",null,"The following fields should be filled out on this page:"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Setting"),(0,r.kt)("th",{parentName:"tr",align:null},"Value"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Audience (EntityID)"),(0,r.kt)("td",{parentName:"tr",align:null},"This should be the same as your Firezone ",(0,r.kt)("inlineCode",{parentName:"td"},"SAML_ENTITY_ID"),", defaults to ",(0,r.kt)("inlineCode",{parentName:"td"},"urn:firezone.dev:firezone-app"),".")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Recipient"),(0,r.kt)("td",{parentName:"tr",align:null},"This is your Firezone ",(0,r.kt)("inlineCode",{parentName:"td"},"EXTERNAL_URL/auth/saml/sp/consume/:config_id")," (e.g., ",(0,r.kt)("inlineCode",{parentName:"td"},"https://firezone.company.com/auth/saml/sp/consume/onelogin"),").")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"ACS URL Validator"),(0,r.kt)("td",{parentName:"tr",align:null},"This field is regex to ensure OneLogin posts the response to the correct URL. For the sample URL below, we can use ",(0,r.kt)("inlineCode",{parentName:"td"},"^https:\\/\\/firezone\\.company\\.com\\/auth\\/saml\\/sp\\/consume\\/onelogin"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"ACS URL"),(0,r.kt)("td",{parentName:"tr",align:null},"This is your Firezone ",(0,r.kt)("inlineCode",{parentName:"td"},"EXTERNAL_URL/auth/saml/sp/consume/:config_id")," (e.g., ",(0,r.kt)("inlineCode",{parentName:"td"},"https://firezone.company.com/auth/saml/sp/consume/onelogin"),").")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Login URL"),(0,r.kt)("td",{parentName:"tr",align:null},"This is your Firezone ",(0,r.kt)("inlineCode",{parentName:"td"},"EXTERNAL_URL/auth/saml/auth/signin/:config_id")," (e.g., ",(0,r.kt)("inlineCode",{parentName:"td"},"https://firezone.company.com/auth/saml/sp/consume/onelogin"),").")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"SAML initiator"),(0,r.kt)("td",{parentName:"tr",align:null},"Service Provider")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"SAML signature element"),(0,r.kt)("td",{parentName:"tr",align:null},"Both")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Encrypt Assertion"),(0,r.kt)("td",{parentName:"tr",align:null},"Checked.")))),(0,r.kt)("p",null,(0,r.kt)("a",{parentName:"p",href:"https://onelogin.service-now.com/support?id=kb_article&sys_id=912bb23edbde7810fe39dde7489619de&kb_category=93e869b0db185340d5505eea4b961934"},"OneLogin's docs"),"\nprovide a good overview of each field's purpose."),(0,r.kt)("p",null,(0,r.kt)("img",{parentName:"p",src:"https://user-images.githubusercontent.com/52545545/202557656-07b809db-51ba-4133-ae4c-c45ebf40401b.png",alt:"OneLogin Configs"})),(0,r.kt)("p",null,"Once complete, save the changes and download the SAML metadata document\nfound unde the ",(0,r.kt)("inlineCode",{parentName:"p"},"More Actions")," dropdown. You'll need\nto copy-paste the contents of this document into the Firezone portal in the next step."),(0,r.kt)("h2",{id:"step-2-add-saml-identity-provider-to-firezone"},"Step 2: Add SAML identity provider to Firezone"),(0,r.kt)("p",null,"In the Firezone portal, add a SAML identity provider under the Security tab\nby filling out the following information:"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Setting"),(0,r.kt)("th",{parentName:"tr",align:null},"Value"),(0,r.kt)("th",{parentName:"tr",align:null},"Notes"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Config ID"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"onelogin")),(0,r.kt)("td",{parentName:"tr",align:null},"Used to construct endpoints required in the SAML authentication flow (e.g., receiving assertions, login requests).")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Label"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"OneLogin")),(0,r.kt)("td",{parentName:"tr",align:null},"Appears on the sign in button for authentication.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Metadata"),(0,r.kt)("td",{parentName:"tr",align:null},"see note"),(0,r.kt)("td",{parentName:"tr",align:null},"Paste the contents of the SAML metadata document you downloaded in the previous step from OneLogin.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Sign assertions"),(0,r.kt)("td",{parentName:"tr",align:null},"Checked."),(0,r.kt)("td",{parentName:"tr",align:null})),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Sign metadata"),(0,r.kt)("td",{parentName:"tr",align:null},"Checked."),(0,r.kt)("td",{parentName:"tr",align:null})),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Require signed assertions"),(0,r.kt)("td",{parentName:"tr",align:null},"Checked."),(0,r.kt)("td",{parentName:"tr",align:null})),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Required signed envelopes"),(0,r.kt)("td",{parentName:"tr",align:null},"Checked."),(0,r.kt)("td",{parentName:"tr",align:null})),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Auto create users"),(0,r.kt)("td",{parentName:"tr",align:null},"Default ",(0,r.kt)("inlineCode",{parentName:"td"},"false")),(0,r.kt)("td",{parentName:"tr",align:null},"Enable this setting to automatically create users when signing in with this connector for the first time. Disable to manually create users.")))),(0,r.kt)("p",null,(0,r.kt)("img",{parentName:"p",src:"https://user-images.githubusercontent.com/52545545/202556102-5ba29d84-9610-4ffa-a516-6c89ffef4928.png",alt:"OneLogin SAML"})),(0,r.kt)("p",null,"After saving the SAML config, you should see a ",(0,r.kt)("inlineCode",{parentName:"p"},"Sign in with OneLogin")," button\non your Firezone portal sign-in page."))}c.isMDXComponent=!0}}]);