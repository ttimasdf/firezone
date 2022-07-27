"use strict";(self.webpackChunknew_docs=self.webpackChunknew_docs||[]).push([[4752],{3905:function(e,n,r){r.d(n,{Zo:function(){return f},kt:function(){return m}});var t=r(7294);function i(e,n,r){return n in e?Object.defineProperty(e,n,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[n]=r,e}function o(e,n){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);n&&(t=t.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),r.push.apply(r,t)}return r}function a(e){for(var n=1;n<arguments.length;n++){var r=null!=arguments[n]?arguments[n]:{};n%2?o(Object(r),!0).forEach((function(n){i(e,n,r[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(r,n))}))}return e}function c(e,n){if(null==e)return{};var r,t,i=function(e,n){if(null==e)return{};var r,t,i={},o=Object.keys(e);for(t=0;t<o.length;t++)r=o[t],n.indexOf(r)>=0||(i[r]=e[r]);return i}(e,n);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(t=0;t<o.length;t++)r=o[t],n.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var u=t.createContext({}),s=function(e){var n=t.useContext(u),r=n;return e&&(r="function"==typeof e?e(n):a(a({},n),e)),r},f=function(e){var n=s(e.components);return t.createElement(u.Provider,{value:n},e.children)},p={inlineCode:"code",wrapper:function(e){var n=e.children;return t.createElement(t.Fragment,{},n)}},l=t.forwardRef((function(e,n){var r=e.components,i=e.mdxType,o=e.originalType,u=e.parentName,f=c(e,["components","mdxType","originalType","parentName"]),l=s(r),m=i,d=l["".concat(u,".").concat(m)]||l[m]||p[m]||o;return r?t.createElement(d,a(a({ref:n},f),{},{components:r})):t.createElement(d,a({ref:n},f))}));function m(e,n){var r=arguments,i=n&&n.mdxType;if("string"==typeof e||i){var o=r.length,a=new Array(o);a[0]=l;var c={};for(var u in n)hasOwnProperty.call(n,u)&&(c[u]=n[u]);c.originalType=e,c.mdxType="string"==typeof e?e:i,a[1]=c;for(var s=2;s<o;s++)a[s]=r[s];return t.createElement.apply(null,a)}return t.createElement.apply(null,r)}l.displayName="MDXCreateElement"},3063:function(e,n,r){r.r(n),r.d(n,{assets:function(){return f},contentTitle:function(){return u},default:function(){return m},frontMatter:function(){return c},metadata:function(){return s},toc:function(){return p}});var t=r(7462),i=r(3366),o=(r(7294),r(3905)),a=["components"],c={title:"Configure",sidebar_position:1},u=void 0,s={unversionedId:"administer/configure",id:"administer/configure",title:"Configure",description:"Firezone leverages Chef Omnibus to handle",source:"@site/docs/administer/configure.md",sourceDirName:"administer",slug:"/administer/configure",permalink:"/administer/configure",draft:!1,editUrl:"https://github.com/firezone/firezone/docs/administer/configure.md",tags:[],version:"current",sidebarPosition:1,frontMatter:{title:"Configure",sidebar_position:1},sidebar:"tutorialSidebar",previous:{title:"Administer",permalink:"/administer/"},next:{title:"Manage Installation",permalink:"/administer/manage"}},f={},p=[],l={toc:p};function m(e){var n=e.components,r=(0,i.Z)(e,a);return(0,o.kt)("wrapper",(0,t.Z)({},l,r,{components:n,mdxType:"MDXLayout"}),(0,o.kt)("p",null,"Firezone leverages ",(0,o.kt)("a",{parentName:"p",href:"https://github.com/chef/omnibus"},"Chef Omnibus")," to handle\nrelease packaging, process supervision, log management, and more."),(0,o.kt)("p",null,"The main configuration file is written in ",(0,o.kt)("a",{parentName:"p",href:"https://ruby-lang.org"},"Ruby")," and can\nbe found at ",(0,o.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb"),". Changing this file ",(0,o.kt)("strong",{parentName:"p"},"requires\nre-running")," ",(0,o.kt)("inlineCode",{parentName:"p"},"sudo firezone-ctl reconfigure")," which triggers Chef to pick up the\nchanges and apply them to the running system."),(0,o.kt)("p",null,"For an exhaustive list of configuration variables and their descriptions, see the\n",(0,o.kt)("a",{parentName:"p",href:"../reference/configuration-file"},"configuration file reference"),"."))}m.isMDXComponent=!0}}]);