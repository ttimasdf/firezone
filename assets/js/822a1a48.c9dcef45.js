"use strict";(self.webpackChunknew_docs=self.webpackChunknew_docs||[]).push([[4649],{3905:function(e,n,t){t.d(n,{Zo:function(){return u},kt:function(){return f}});var r=t(7294);function a(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function i(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);n&&(r=r.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,r)}return t}function o(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?i(Object(t),!0).forEach((function(n){a(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):i(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function s(e,n){if(null==e)return{};var t,r,a=function(e,n){if(null==e)return{};var t,r,a={},i=Object.keys(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||(a[t]=e[t]);return a}(e,n);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(a[t]=e[t])}return a}var c=r.createContext({}),l=function(e){var n=r.useContext(c),t=n;return e&&(t="function"==typeof e?e(n):o(o({},n),e)),t},u=function(e){var n=l(e.components);return r.createElement(c.Provider,{value:n},e.children)},d={inlineCode:"code",wrapper:function(e){var n=e.children;return r.createElement(r.Fragment,{},n)}},p=r.forwardRef((function(e,n){var t=e.components,a=e.mdxType,i=e.originalType,c=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),p=l(t),f=a,m=p["".concat(c,".").concat(f)]||p[f]||d[f]||i;return t?r.createElement(m,o(o({ref:n},u),{},{components:t})):r.createElement(m,o({ref:n},u))}));function f(e,n){var t=arguments,a=n&&n.mdxType;if("string"==typeof e||a){var i=t.length,o=new Array(i);o[0]=p;var s={};for(var c in n)hasOwnProperty.call(n,c)&&(s[c]=n[c]);s.originalType=e,s.mdxType="string"==typeof e?e:a,o[1]=s;for(var l=2;l<i;l++)o[l]=t[l];return r.createElement.apply(null,o)}return r.createElement.apply(null,t)}p.displayName="MDXCreateElement"},1209:function(e,n,t){t.r(n),t.d(n,{assets:function(){return u},contentTitle:function(){return c},default:function(){return f},frontMatter:function(){return s},metadata:function(){return l},toc:function(){return d}});var r=t(7462),a=t(3366),i=(t(7294),t(3905)),o=["components"],s={title:"Manage Installation",sidebar_position:2},c=void 0,l={unversionedId:"administer/manage",id:"administer/manage",title:"Manage Installation",description:"Your Firezone installation can be managed via the firezone-ctl command, as",source:"@site/docs/administer/manage.md",sourceDirName:"administer",slug:"/administer/manage",permalink:"/administer/manage",draft:!1,editUrl:"https://github.com/firezone/firezone/docs/administer/manage.md",tags:[],version:"current",sidebarPosition:2,frontMatter:{title:"Manage Installation",sidebar_position:2},sidebar:"tutorialSidebar",previous:{title:"Configure",permalink:"/administer/configure"},next:{title:"Upgrade",permalink:"/administer/upgrade"}},u={},d=[],p={toc:d};function f(e){var n=e.components,t=(0,a.Z)(e,o);return(0,i.kt)("wrapper",(0,r.Z)({},p,t,{components:n,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Your Firezone installation can be managed via the ",(0,i.kt)("inlineCode",{parentName:"p"},"firezone-ctl")," command, as\nshown below. Most subcommands require prefixing with ",(0,i.kt)("inlineCode",{parentName:"p"},"sudo"),"."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-text"},"root@demo:~# firezone-ctl\nI don't know that command.\nomnibus-ctl: command (subcommand)\nGeneral Commands:\n  cleanse\n    Delete *all* firezone data, and start from scratch.\n  create-or-reset-admin\n    Resets the password for admin with email specified by default['firezone']['admin_email'] or creates a new admin if that email doesn't exist.\n  help\n    Print this help message.\n  reconfigure\n    Reconfigure the application.\n  reset-network\n    Resets nftables, WireGuard interface, and routing table back to Firezone defaults.\n  show-config\n    Show the configuration that would be generated by reconfigure.\n  teardown-network\n    Removes WireGuard interface and firezone nftables table.\n  force-cert-renewal\n    Force certificate renewal now even if it hasn\\'t expired.\n  stop-cert-renewal\n    Removes cronjob that renews certificates.\n  uninstall\n    Kill all processes and uninstall the process supervisor (data will be preserved).\n  version\n    Display current version of Firezone\nService Management Commands:\n  graceful-kill\n    Attempt a graceful stop, then SIGKILL the entire process group.\n  hup\n    Send the services a HUP.\n  int\n    Send the services an INT.\n  kill\n    Send the services a KILL.\n  once\n    Start the services if they are down. Do not restart them if they stop.\n  restart\n    Stop the services if they are running, then start them again.\n  service-list\n    List all the services (enabled services appear with a *.)\n  start\n    Start services if they are down, and restart them if they stop.\n  status\n    Show the status of all the services.\n  stop\n    Stop the services, and do not restart them.\n  tail\n    Watch the service logs of all enabled services.\n  term\n    Send the services a TERM.\n  usr1\n    Send the services a USR1.\n  usr2\n    Send the services a USR2.\n")))}f.isMDXComponent=!0}}]);