"use strict";(self.webpackChunkfirezone_docs=self.webpackChunkfirezone_docs||[]).push([[161],{3905:(e,t,n)=>{n.d(t,{Zo:()=>s,kt:()=>k});var a=n(7294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function l(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function i(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},o=Object.keys(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var d=a.createContext({}),p=function(e){var t=a.useContext(d),n=t;return e&&(n="function"==typeof e?e(t):l(l({},t),e)),n},s=function(e){var t=p(e.components);return a.createElement(d.Provider,{value:t},e.children)},m="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},c=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,o=e.originalType,d=e.parentName,s=i(e,["components","mdxType","originalType","parentName"]),m=p(n),c=r,k=m["".concat(d,".").concat(c)]||m[c]||u[c]||o;return n?a.createElement(k,l(l({ref:t},s),{},{components:n})):a.createElement(k,l({ref:t},s))}));function k(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var o=n.length,l=new Array(o);l[0]=c;var i={};for(var d in t)hasOwnProperty.call(t,d)&&(i[d]=t[d]);i.originalType=e,i[m]="string"==typeof e?e:r,l[1]=i;for(var p=2;p<o;p++)l[p]=n[p];return a.createElement.apply(null,l)}return a.createElement.apply(null,n)}c.displayName="MDXCreateElement"},1940:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>d,contentTitle:()=>l,default:()=>g,frontMatter:()=>o,metadata:()=>i,toc:()=>p});var a=n(7462),r=(n(7294),n(3905));const o={title:"Custom External Database",sidebar_position:2},l=void 0,i={unversionedId:"deploy/advanced/external-database",id:"deploy/advanced/external-database",title:"Custom External Database",description:"Firezone uses Postgresql DB as its primary data store.",source:"@site/docs/deploy/advanced/external-database.mdx",sourceDirName:"deploy/advanced",slug:"/deploy/advanced/external-database",permalink:"/deploy/advanced/external-database",draft:!1,editUrl:"https://github.com/firezone/firezone/tree/master/www/docs/deploy/advanced/external-database.mdx",tags:[],version:"current",sidebarPosition:2,frontMatter:{title:"Custom External Database",sidebar_position:2},sidebar:"tutorialSidebar",previous:{title:"Build From Source",permalink:"/deploy/advanced/build-from-source"},next:{title:"Custom Reverse Proxy",permalink:"/deploy/advanced/reverse-proxy"}},d={},p=[{value:"Compatibility",id:"compatibility",level:2},{value:"Configure Firezone to Connect",id:"configure-firezone-to-connect",level:2}],s=e=>function(t){return console.warn("Component "+e+" was not imported, exported, or provided by MDXProvider as global scope"),(0,r.kt)("div",t)},m=s("Tabs"),u=s("TabItem"),c={toc:p},k="wrapper";function g(e){let{components:t,...n}=e;return(0,r.kt)(k,(0,a.Z)({},c,n,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("p",null,"Firezone uses ",(0,r.kt)("a",{parentName:"p",href:"https://postgresql.org"},"Postgresql DB")," as its primary data store."),(0,r.kt)("h2",{id:"compatibility"},"Compatibility"),(0,r.kt)("p",null,"Firezone should work fine on Postgres versions 12 and above, but we recommend\nusing the latest stable version whenever possible. If you find an issue with\nyour particular version of Postgres, ",(0,r.kt)("a",{parentName:"p",href:"https://github.com/firezone/firezone/issues"},"please open a GitHub issue\n"),"."),(0,r.kt)("p",null,"In general, Firezone should also work fine using external Postgres-based\ndatabase services like Amazon RDS. See the ",(0,r.kt)("a",{parentName:"p",href:"#configure-firezone-to-connect"},"configuration\n")," section below for more information configuring\nFirezone with an external DB."),(0,r.kt)("admonition",{type:"warning"},(0,r.kt)("p",{parentName:"admonition"},"Configuring Firezone to use an external database can be complicated and\nerror-prone. We recommend using the bundled Postgres for Omnibus-based\ndeployments or the official Postgres Docker image for Docker-based deployments\nif possible.")),(0,r.kt)("admonition",{type:"info"},(0,r.kt)("p",{parentName:"admonition"},"Need help deploying or maintaining Firezone with an external database? Consider\n",(0,r.kt)("a",{parentName:"p",href:"https://www.firezone.dev/contact/sales?utm_source=docs.firezone.dev"},"contacting us about our Enterprise Plan")," for\nrecommended configurations, white-glove deployment assistance, and more.")),(0,r.kt)("h2",{id:"configure-firezone-to-connect"},"Configure Firezone to Connect"),(0,r.kt)(m,{mdxType:"Tabs"},(0,r.kt)(u,{value:"docker",label:"Docker",default:!0,mdxType:"TabItem"},(0,r.kt)("p",null,"The Firezone Docker image uses the following environment\nvariables to connect to the DB (fields in bold required):"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Name"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"),(0,r.kt)("th",{parentName:"tr",align:null},"Format"),(0,r.kt)("th",{parentName:"tr",align:null},"Default"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"DATABASE_ENCRYPTION_KEY"))),(0,r.kt)("td",{parentName:"tr",align:null},"The base64-encoded symmetric encryption key used to encrypt and decrypt sensitive fields."),(0,r.kt)("td",{parentName:"tr",align:null},"base64-encoded String"),(0,r.kt)("td",{parentName:"tr",align:null},"None -- must be generated on install")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_HOST")),(0,r.kt)("td",{parentName:"tr",align:null},"Database host"),(0,r.kt)("td",{parentName:"tr",align:null},"IP or hostname"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"postgres"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_PORT")),(0,r.kt)("td",{parentName:"tr",align:null},"Database port"),(0,r.kt)("td",{parentName:"tr",align:null},"Integer"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"5432"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_NAME")),(0,r.kt)("td",{parentName:"tr",align:null},"Name of database"),(0,r.kt)("td",{parentName:"tr",align:null},"String"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"firezone"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_USER")),(0,r.kt)("td",{parentName:"tr",align:null},"User"),(0,r.kt)("td",{parentName:"tr",align:null},"String"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"postgres"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_PASSWORD")),(0,r.kt)("td",{parentName:"tr",align:null},"Password"),(0,r.kt)("td",{parentName:"tr",align:null},"String"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"postgres"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_POOL")),(0,r.kt)("td",{parentName:"tr",align:null},"Size of the Firezone connection pool"),(0,r.kt)("td",{parentName:"tr",align:null},"Integer"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"10"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_SSL")),(0,r.kt)("td",{parentName:"tr",align:null},"Whether to connect to the database over SSL"),(0,r.kt)("td",{parentName:"tr",align:null},"Boolean"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"false"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_SSL_OPTS")),(0,r.kt)("td",{parentName:"tr",align:null},"Map of options to send to the ",(0,r.kt)("inlineCode",{parentName:"td"},":ssl_opts")," option when connecting over SSL. See ",(0,r.kt)("a",{parentName:"td",href:"https://hexdocs.pm/ecto_sql/Ecto.Adapters.Postgres.html#module-connection-options"},"Ecto.Adapters.Postgres documentation")),(0,r.kt)("td",{parentName:"tr",align:null},"JSON-encoded String"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"{}"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"DATABASE_PARAMETERS")),(0,r.kt)("td",{parentName:"tr",align:null},"Map of parameters to send to the ",(0,r.kt)("inlineCode",{parentName:"td"},":parameters")," option when connecting to the database. See ",(0,r.kt)("a",{parentName:"td",href:"https://hexdocs.pm/ecto_sql/Ecto.Adapters.Postgres.html#module-connection-options"},"Ecto.Adapters.Postgres documentation"),"."),(0,r.kt)("td",{parentName:"tr",align:null},"JSON-encoded String"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"{}"))))),(0,r.kt)("p",null,"For more information, see the ",(0,r.kt)("a",{parentName:"p",href:"/reference/env-vars/"},"environment variable reference\n"),"."),(0,r.kt)("admonition",{type:"note"},(0,r.kt)("p",{parentName:"admonition"},"The official ",(0,r.kt)("inlineCode",{parentName:"p"},"postgres")," docker image can be configured by setting\nenvironment variables for the container. See the Postgres image\n",(0,r.kt)("a",{parentName:"p",href:"https://hub.docker.com/_/postgres"},"documentation")," for more details."))),(0,r.kt)(u,{value:"omnibus",label:"Omnibus",mdxType:"TabItem"},(0,r.kt)("p",null,"The following configuration options are used to configure the bundled Postgres\nfor Omnibus-based deployments:"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Config Key"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"),(0,r.kt)("th",{parentName:"tr",align:null},"Default"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['user']")),(0,r.kt)("td",{parentName:"tr",align:null},"Specifies the username Firezone will use to connect to the DB."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"node['firezone']['postgresql']['username']"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['password']")),(0,r.kt)("td",{parentName:"tr",align:null},"If using an external DB, specifies the password Firezone will use to connect to the DB."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"'change_me'"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['name']")),(0,r.kt)("td",{parentName:"tr",align:null},"Database that Firezone will use. Will be created if it doesn't exist."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"'firezone'"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['host']")),(0,r.kt)("td",{parentName:"tr",align:null},"Database host that Firezone will connect to."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"node['firezone']['postgresql']['listen_address']"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['port']")),(0,r.kt)("td",{parentName:"tr",align:null},"Database port that Firezone will connect to."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"node['firezone']['postgresql']['port']"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['pool']")),(0,r.kt)("td",{parentName:"tr",align:null},"Database pool size Firezone will use."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"[10, Etc.nprocessors].max"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['ssl']")),(0,r.kt)("td",{parentName:"tr",align:null},"Whether to connect to the database over SSL."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"false"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['ssl_opts']")),(0,r.kt)("td",{parentName:"tr",align:null},"Hash of options to send to the ",(0,r.kt)("inlineCode",{parentName:"td"},":ssl_opts")," option when connecting over SSL. See ",(0,r.kt)("a",{parentName:"td",href:"https://hexdocs.pm/ecto_sql/Ecto.Adapters.Postgres.html#module-connection-options"},"Ecto.Adapters.Postgres documentation"),"."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"{}"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['parameters']")),(0,r.kt)("td",{parentName:"tr",align:null},"Hash of parameters to send to the ",(0,r.kt)("inlineCode",{parentName:"td"},":parameters")," option when connecting to the database. See ",(0,r.kt)("a",{parentName:"td",href:"https://hexdocs.pm/ecto_sql/Ecto.Adapters.Postgres.html#module-connection-options"},"Ecto.Adapters.Postgres documentation"),"."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"{}"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"default['firezone']['database']['extensions']")),(0,r.kt)("td",{parentName:"tr",align:null},"Database extensions to enable."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"{ 'plpgsql' => true, 'pg_trgm' => true }"))))),(0,r.kt)("p",null,"For more details, see the ",(0,r.kt)("a",{parentName:"p",href:"/reference/configuration-file/"},"configuration file reference\n"),"."))))}g.isMDXComponent=!0}}]);