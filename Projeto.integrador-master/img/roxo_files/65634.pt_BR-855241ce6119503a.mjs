"use strict";(self.__LOADABLE_LOADED_CHUNKS__=self.__LOADABLE_LOADED_CHUNKS__||[]).push([[65634],{385973:(e,t,i)=>{i.r(t),i.d(t,{default:()=>r});let n={argumentDefinitions:[],kind:"Fragment",metadata:null,name:"ShoppingModulePreviewImages_story",selections:[{alias:null,args:null,concreteType:null,kind:"LinkedField",name:"objects",plural:!0,selections:[{alias:null,args:null,kind:"ScalarField",name:"__typename",storageKey:null},{kind:"InlineFragment",selections:[{alias:"imageSpec_236x",args:[{kind:"Literal",name:"spec",value:"236x"}],concreteType:"ImageDetails",kind:"LinkedField",name:"images",plural:!1,selections:[{alias:null,args:null,kind:"ScalarField",name:"url",storageKey:null}],storageKey:'images(spec:"236x")'}],type:"Pin",abstractKey:null}],storageKey:null}],type:"Story",abstractKey:null};n.hash="d06bcbcd23746aa04d9f42cb2af2084d";let r=n},590919:(e,t,i)=>{i.d(t,{Z:()=>u});var n=i(667294),r=i(883119),o=i(666472),l=i(340523),a=i(106581),s=i(483166),d=i(785893);function c(e){let t=(0,n.useRef)(null),i=t.current?.clientWidth??void 0,o={...e,width:i};return(0,d.jsx)(r.xu,{ref:t,children:(0,d.jsx)(s.Z,{largeSizeRep:(0,d.jsx)(a.default,{...o,contentVisibleItemCountOverride:3.5}),mediumSizeRep:(0,d.jsx)(a.default,{...o,contentVisibleItemCountOverride:3.5}),smallSizeRep:(0,d.jsx)(a.default,{...o,contentVisibleItemCountOverride:2.5})})})}function u(e){let{auxData:t,contentIds:i,story:n,slotIndex:s,viewParameter:u,viewType:p,...h}=e,_=(0,o.Z)({clientTrackingParams:n?.tracking_params,componentType:n?.display_options?.content_display?.component_type,contextLogData:{content_ids:i??n?.objects?.map(({type:e,id:t})=>`${e??""}:${t??""}`).join("|"),grid_index:s,story_id:n?.id,story_type:n?.story_type,total_object_count:n?.objects?.length,...t},impressionType:"Story",loggingId:n?.id,objectIdStr:n?.id,slotIndex:s,viewParameter:u,viewType:p}),{checkExperiment:x}=(0,l.F)(),y=n?.story_type==="recently_viewed"&&x("web_recently_viewed_responsive").anyEnabled,g={...h,initialSlotIndex:0,story:n,view:p,viewParameter:u};return n?(0,d.jsx)(r.xu,{ref:_,children:y?(0,d.jsx)(c,{...g,storyKey:{type:"deprecated",data:n}}):(0,d.jsx)(a.default,{...g,storyKey:{type:"deprecated",data:n}})}):null}},658190:(e,t,i)=>{i.d(t,{Z:()=>m});var n=i(667294),r=i(240684),o=i(883119),l=i(725619),a=i(503853),s=i(321329),d=i(173690),c=i(118923),u=i(832853),p=i(785893);let h=(0,r.ZP)({resolved:{},chunkName:()=>"app-www-video-VideoWrapper",isReady(e){let t=this.resolve(e);return!0===this.resolved[t]&&!!i.m[t]},importAsync:()=>Promise.all([i.e(93041),i.e(84452),i.e(95813)]).then(i.bind(i,131348)),requireAsync(e){let t=this.resolve(e);return this.resolved[t]=!1,this.importAsync(e).then(e=>(this.resolved[t]=!0,e))},requireSync(e){return i(this.resolve(e))},resolve:()=>131348}),_=(0,u.Z)(()=>Promise.all([i.e(93041),i.e(84452),i.e(95813)]).then(i.bind(i,131348)),void 0,"app-www-video-VideoWrapper"),x={defaultOverlay:{backgroundColor:"rgba(0, 0, 0, 0.4)"},hoverOverlay:{backgroundColor:"rgba(0, 0, 0, 0.6)"}},y=e=>(0,c.b)()?(0,p.jsx)(_,{...e}):(0,p.jsx)(h,{...e});function g({titleText:e,videoPin:t,videoPlaceholderImage:i}){return(0,p.jsx)(y,{aspectRatio:a.q4,captions:"",controls:!1,fallback:(0,p.jsx)(o.Ee,{alt:e||"",color:"rgb(111, 91, 77)",fit:"cover",naturalHeight:3,naturalWidth:2,src:i||t.metadata.thumbnail}),isAutoPlay:!0,loop:!0,onPlay:()=>{},onPlayError:()=>{},playing:!0,playsInline:!0,poster:i||t.metadata.thumbnail,src:t.url,volume:0})}function m({buttonAction:e,buttonCustomization:t,buttonText:i,experience:r,hideCompleteButton:c,imageAlt:u,imageUrl:h,openNewTab:_,storyType:y,titleColor:m,titleText:v,titleTextCustomization:f,videoPin:j,videoPlaceholderImage:b}){let[w,S]=(0,n.useState)(!1),{experience_id:P,placement_id:I}=r||{},k=(0,s.Z)(I),E=(0,d.Z)({onVisibilityChanged:e=>{e&&r&&"viewed"!==r.status&&void 0!==I&&void 0!==P&&(r.status="viewed",k.viewExperience(I,P,!1,!0))}}),Z=()=>{r&&k.completeExperience(I,P,!1,!0)},C=()=>{S(!0)},T=()=>{S(!1)},z="feed_card_video"===y?354:315,A=(0,a.zn)(y),O=A?l.f8:l.hm,R=A?l.sH:l.HI,{color:M,fontSize:F,fontStyle:L,fontWeight:B,horizontalAlignment:D}=(0,a.Mf)(f||{},"web");return(0,p.jsxs)(o.xu,{ref:E,position:"relative",children:[(0,p.jsx)(o.xu,{onMouseEnter:C,onMouseLeave:T,children:(0,p.jsxs)(o.rU,{accessibilityLabel:v,href:e,onBlur:T,onClick:Z,onFocus:C,target:_?"blank":null,underline:"none",children:[(0,p.jsxs)(o.xu,{dangerouslySetInlineStyle:{__style:{paddingBottom:`${z/236*100}%`,WebkitMaskImage:"-webkit-radial-gradient(white, black)"}},overflow:"hidden",position:"relative",rounding:4,width:"100%",children:[(0,p.jsx)(o.xu,{height:"100%",position:"absolute",rounding:4,width:"100%",children:"feed_card_video"===y&&j?(0,p.jsx)(g,{titleText:v,videoPin:j,videoPlaceholderImage:b}):h&&(0,p.jsx)(o.Ee,{alt:u||"",color:"rgb(111, 91, 77)",fit:"cover",naturalHeight:4,naturalWidth:3,src:h})}),!A&&(0,p.jsx)(o.xu,{dangerouslySetInlineStyle:{__style:w?x.hoverOverlay:x.defaultOverlay},height:"100%",left:!0,position:"absolute",top:!0,width:"100%"}),(0,p.jsx)(O,{children:(0,p.jsx)(o.xv,{align:D,color:m,italic:"italics"===L,weight:B,children:(0,p.jsx)(o.xu,{dangerouslySetInlineStyle:{__style:{color:M??void 0,fontSize:F}},children:v})})})]}),!c&&A&&(0,p.jsx)(R,{children:(0,p.jsx)(o.zx,{color:(0,a.pQ)(t),text:i})})]})}),!A&&(0,p.jsx)(R,{children:(0,p.jsx)(o.ZP,{accessibilityLabel:i,color:"gray",fullWidth:!0,href:e,onClick:Z,size:"lg",text:i})})]})}},793722:(e,t,i)=>{i.r(t),i.d(t,{default:()=>z});var n=i(616550),r=i(883119),o=i(397210),l=i(785893);function a({slotIndex:e,story:t}){return(0,l.jsx)(o.Z,{isInViewOrNext:!0,item:t.objects?.[0],slotIndex:e,story:t})}function s({story:e}){return(0,l.jsxs)(r.xu,{marginBottom:6,children:[(0,l.jsx)(r.xv,{align:"center",size:"500",weight:"bold",children:e.title?.format}),e.objects?.map((t,i)=>l.jsx(r.xu,{marginTop:4,children:l.jsx(o.Z,{component:14269,isInViewOrNext:!0,item:t,slotIndex:i,story:e,view:1,viewParameter:null})},i))]})}var d=i(590919),c=i(658190),u=i(667294),p=i(545007),h=i(214877),_=i(25919);function x({experienceId:e,copy:{buttonText:t,subtitleText:i,titleText:o},path:a,pins:s,placementId:d}){let{logContextEvent:c}=(0,h.v)(),x=(0,p.I0)(),y=(0,n.k6)(),g=(0,_.Ig)(),m=(0,_.be)();(0,u.useEffect)(()=>{c({event_type:13,view_type:1,view_parameter:92,component:200,element:10551}),x(g(d,e,!1,!0))},[]);let v=(e,t)=>{let{height:i,url:n,width:o}=e.images.orig;return(0,l.jsx)(r.xu,{marginStart:0===t?0:2,children:(0,l.jsx)(r.zd,{height:72,rounding:2,width:48,children:(0,l.jsx)(r.Ee,{alt:"",color:"",fit:"cover",naturalHeight:i,naturalWidth:o,src:n})})},e.id)};return(0,l.jsxs)(r.kC,{alignItems:"stretch",dataTestId:"story-landing-page-card",direction:"column",flex:"grow",justifyContent:"start",children:[(0,l.jsx)(r.xu,{paddingY:1,children:(0,l.jsx)(r.X6,{align:"center",size:"400",children:o})}),(0,l.jsx)(r.xu,{paddingY:1,children:(0,l.jsx)(r.xv,{align:"center",children:i})}),(0,l.jsx)(r.xu,{alignItems:"center",display:"flex",justifyContent:"center",marginTop:1,paddingY:2,children:s&&s.map((e,t)=>v(e,t))}),(0,l.jsx)(r.xu,{alignSelf:"center",paddingY:2,children:(0,l.jsx)(r.zx,{fullWidth:!0,onClick:()=>{x(m(d,e,!1,!0)),c({event_type:101,view_type:1,view_parameter:92,component:200,element:10551}),y.push(a)},size:"lg",text:t})})]})}var y=i(503853),g=i(666472),m=i(256683),v=i(340523),f=i(325362),j=i(536793),b=i(624797),w=i(549629),S=i(888973),P=i(477458);let I=[{top:"18px",left:"8px",transform:"rotate(2.25deg)",height:88,width:60},{left:"58px",transform:"rotate(-5deg)",height:111,width:77},{top:"9px",left:"122px",transform:"rotate(5deg)",height:90,width:65},{top:"15px",left:"164px",transform:"rotate(-2.25deg)",height:88,width:60}];function k({auxData:e,objects:t,text:i,url:n,viewParameterType:o,viewType:a}){let s=!i||!n,{logContextEvent:d}=(0,h.v)(),c={aux_data:e,component:15111,view_parameter:o,view_type:a};if(s)return null;let u=t?.map(e=>{let t=e.cover_images?.[0];return t?S.Z({imageSizeToImageMap:t,preferredSize:"236x"}):null}).filter(Boolean).slice(0,4);return(0,l.jsx)(w.Z,{log:c,children:(0,l.jsx)(P.q,{children:({hovered:e,onMouseEnter:t,onMouseLeave:o})=>(0,l.jsx)(r.rU,{accessibilityLabel:i,href:n,onBlur:o,onClick:()=>{d({...c,event_type:101})},onFocus:t,underline:"none",children:(0,l.jsxs)(r.xu,{dangerouslySetInlineStyle:{__style:{border:"2px solid #E9E9E9"}},minHeight:238,onMouseEnter:t,onMouseLeave:o,paddingY:8,position:"relative",rounding:4,children:[(0,l.jsx)(r.xu,{color:"default",height:"100%",position:"absolute",zIndex:new r.Ry(-2)}),(0,l.jsx)(r.xu,{marginBottom:6,marginEnd:4,marginStart:4,children:(0,l.jsx)(r.xv,{color:"dark",lineClamp:4,size:"500",weight:"bold",children:i})}),(0,l.jsx)(r.xu,{height:113,position:"relative",children:u.map(({url:e,dominant_color:t},i)=>{let n=I[i];return(0,l.jsx)(r.xu,{dangerouslySetInlineStyle:{__style:{border:"1px solid white",boxShadow:"0px 2px 8px 0px rgba(0, 0, 0, 0.12)",...n}},overflow:"hidden",position:"absolute",rounding:2,children:(0,l.jsx)(r.Ee,{alt:"",color:t||"transparent",fit:"cover",naturalHeight:1,naturalWidth:1,role:"presentation",src:e||"",children:(0,l.jsx)(r.zd,{height:n.height,wash:!0,width:n.width,children:(0,l.jsx)(r.xu,{height:n.height,width:n.width})})})},e)})}),(0,l.jsx)(r.xu,{dangerouslySetInlineStyle:{__style:{pointerEvents:"none",right:"-2px",top:"-2px",height:"calc(100% + 4px)",backgroundColor:"#E9E9E9"}},opacity:e?1:0,position:"absolute",rounding:4,zIndex:new r.Ry(-1)})]})})})})}let E=e=>{if(!e)return 0;let t=114/(e.width??1);return Math.floor((e.height??1)*t)};function Z({auxData:e,objects:t,text:i,url:n,viewParameterType:o,viewType:a}){let s=!i||!n||!t,{logContextEvent:d}=(0,h.v)(),c={aux_data:e,component:15111,view_parameter:o,view_type:a},p=(0,u.useMemo)(()=>{let e=t?.map(e=>e.cover_images?.[0]?.["236x"]).filter(Boolean).slice(0,9);return e?[{type:"spacer"},e[0],{type:"spacer"},...e.slice(1,9),e[0],e[1],e[2]]:[]},[t]);if(s)return null;let _=(()=>{let e=i.length>33?294:i.length>22?252:i.length>11?274:299;return Math.abs(e/2-(E(p[1])+12+E(p[6])/2))})();return(0,l.jsx)(w.Z,{log:c,children:(0,l.jsx)(P.q,{children:({hovered:e,onMouseEnter:t,onMouseLeave:o})=>(0,l.jsx)(r.rU,{accessibilityLabel:i,href:n,onBlur:o,onClick:()=>{d({...c,event_type:101})},onFocus:t,underline:"none",children:(0,l.jsxs)(r.xu,{dangerouslySetInlineStyle:{__style:{border:"2px solid #E9E9E9"}},height:i.length>33?420:354,onMouseEnter:t,onMouseLeave:o,overflow:"hidden",position:"relative",rounding:4,children:[(0,l.jsx)(r.xu,{dangerouslySetInlineStyle:{__style:{left:"-18%",top:`-${_}px`}},position:"absolute",width:"133%",zIndex:new r.Ry(-1),children:(0,l.jsx)(r.Rk,{gutterWidth:12,items:p,layout:"flexible",minCols:3,renderItem:({data:e})=>{if("spacer"===e.type)return(0,l.jsx)(r.xu,{height:19});if(!e)return null;let t=E(e);return(0,l.jsx)(r.zd,{height:t,rounding:2,wash:!0,width:"100%",children:(0,l.jsx)(r.xu,{height:t,width:"100%",children:(0,l.jsx)(r.Ee,{alt:"",color:e.dominant_color||"transparent",fit:"cover",naturalHeight:1,naturalWidth:1,role:"presentation",src:e.url||""})})})}})}),(0,l.jsx)(r.xu,{bottom:!0,position:"absolute",width:"100%",children:(0,l.jsx)(r.xu,{color:"default",paddingX:4,paddingY:8,children:(0,l.jsx)(r.xv,{color:"dark",lineClamp:3,size:"500",weight:"bold",children:i})})}),(0,l.jsx)(r.xu,{color:"dark",dangerouslySetInlineStyle:{__style:{pointerEvents:"none"}},height:"100%",opacity:e?.4:0,position:"absolute",top:!0})]})})})})}let C={blended_modules_topic_pin_grid_article:14103,related_query_shop_upsell_search:15111,related_query_shop_upsell_closeup:15111},T={135:14269,136:14268};function z(e){let{checkExperiment:t}=(0,v.F)(),{search:i}=(0,n.TH)(),{isEggsUi:o,itemIdx:u,story:p,surface:h,viewType:_,viewParameter:w}=e,{story_type:S,container_type:P}=p,I=(0,g.Z)({clientTrackingParams:p.tracking_params,componentType:S&&C[S]||"number"==typeof P&&T[P]||void 0,contextLogData:{content_ids:p?.objects?.map(({type:e,id:t})=>`${e??""}:${t??""}`).join("|"),story_id:p.id,story_type:p.story_type,total_object_count:p?.objects?.length,...p.aux_fields??{}},impressionType:"Story",loggingId:p.id,objectIdStr:p?.id,slotIndex:u,viewParameter:w,viewType:_});switch(p.container_type){case 41:let{copy:E,custom_properties:z,experience:A,objects:O}=p;return(0,l.jsx)("div",{className:"Module","data-test-id":"story-card-container",children:(0,l.jsx)(x,{copy:(0,m.Z)(f.Z)(E),experienceId:A.experience_id,path:z?.path,pins:O,placementId:A.placement_id})});case 66:{let{action:e,custom_properties:n,display_options:o,experience:a,objects:s,story_type:d,title:h}=p;if(!["related_query_shop_upsell_search","related_query_shop_upsell_closeup"].includes(d||""))return(0,l.jsx)("div",{ref:I,className:"Module",children:(0,l.jsx)(c.Z,{buttonAction:e?.url,buttonCustomization:n.button_customization,buttonText:e?.text,experience:a,hideCompleteButton:n.hide_complete_button,imageAlt:n.image_alt,imageUrl:n.image,openNewTab:n.open_new_tab,storyType:d,titleColor:(0,y.h_)(n,o.title_text_color),titleText:h.format,titleTextCustomization:n.title_text_customization,videoPin:n.video_pin,videoPlaceholderImage:n.video_placeholder_image})});{let{anyEnabled:n,group:o}=t("related_query_shop_upsell_search"===d?"shopping_unit_search":"shopping_unit_closeup",{dangerouslySkipActivation:!0});if(!n)return null;let a=b.mB(i)?.q,c={auxData:{content_ids:(p.content_ids||[]).map(e=>`${s?.[0].type}:${e}`).join("|"),...a?{entered_query:a}:{},grid_index:u,story_id:p.id,story_index:u,story_type:d},objects:s,text:h?.format,url:e?.url,viewParameterType:w,viewType:_};if(o.match("enabled_frontend_v_two"))return(0,l.jsx)(r.xu,{ref:I,children:(0,l.jsx)(k,{...c})});return(0,l.jsx)(r.xu,{ref:I,children:(0,l.jsx)(Z,{...c})})}}case 135:return(0,l.jsx)("div",{ref:I,className:"Module",children:(0,l.jsx)(s,{slotIndex:u,story:p})});case 136:return(0,l.jsx)("div",{ref:I,className:"Module",children:(0,l.jsx)(a,{slotIndex:u,story:p})});case 90:let R=2===p.display_options.content_display.pins_display;return(0,l.jsx)("div",{className:"Module",children:(0,l.jsx)(d.Z,{gutterWidth:R?8:void 0,isEggsUi:o,slotIndex:u,story:p,styleOverrides:{headerMarginTop:5,headerMarginX:7,carouselPaddingX:18,carouselContainerMarginBottom:1,navigationFabOpacity:1,navigationFabSize:40},surface:h,viewParameter:w,viewType:_})});case 91:if(("blended_module_type_topics_board_recs"===p.story_type||"board_style_pivot"===p.story_type)&&p.objects[0].cover_images.length>=4){let e={item:{action:p.action,cover_images:p.objects[0].cover_images,dominant_colors:p.objects[0].dominant_colors,title:p.title,subtitle:p.subtitle,type:"explorearticle"},slotIndex:u,story:p,view:_,viewParameter:w};return(0,l.jsx)("div",{className:"Module",children:(0,l.jsx)(j.Z,{...e})})}return null;default:return null}}},997485:(e,t,i)=>{i.d(t,{Z:()=>_});var n=i(883119),r=i(50245),o=i(43796),l=i(140017),a=i(785893);function s(){let e=(0,l.ZP)(),t=(0,o.Z)(),i=(0,r.Z)();return(0,a.jsx)(n.zx,{dataTestId:"remove-brand-filter",onClick:()=>{i(0),t([{key:"brands",value:""}])},text:e.bt("Remover marcas", "Remove brands", "AuthSearchPage.PinsNotFoundShoppingFilter.RemoveBrandsFilter", undefined, true)})}function d(){let e=(0,l.ZP)(),t=(0,o.Z)(),i=(0,r.Z)();return(0,a.jsx)(n.zx,{dataTestId:"remove-retailer-filter",onClick:()=>{i(0),t([{key:"domains",value:""}])},text:e.bt("Remover varejistas", "Remove retailers", "AuthSearchPage.PinsNotFoundShoppingFilter.RemoveRetailerFilter", undefined, true)})}function c(){let e=(0,l.ZP)(),t=(0,o.Z)(),i=(0,r.Z)();return(0,a.jsx)(n.zx,{dataTestId:"remove-on-sale-filter",onClick:()=>{i(0),t([{key:"on_sale",value:""}])},text:e.bt("Remover em promoção", "Remove on sale", "AuthSearchPage.PinsNotFoundShoppingFilter.RemoveOnSaleFilter", undefined, true)})}function u(){let e=(0,l.ZP)(),t=(0,o.Z)(),i=(0,r.Z)();return(0,a.jsx)(n.zx,{dataTestId:"remove-price-range-filter",onClick:()=>{i(0),t([{key:"price_min",value:""},{key:"price_max",value:""}])},text:e.bt("Remover preço", "Remove price", "AuthSearchPage.PinsNotFoundShoppingFilter.RemovePriceRangeFilter", undefined, true)})}function p(){let e=(0,l.ZP)(),t=(0,o.Z)(),i=(0,r.Z)();return(0,a.jsx)(n.zx,{dataTestId:"remove-all-filters",onClick:()=>{i(0),t(o.q.map(e=>({key:e,value:""})))},text:e.bt("Limpar todos os filtros", "Clear all filters", "AuthSearchPage.PinsNotFoundShoppingFilter.RemoveProductsFilter", undefined, true)})}var h=i(766323);function _(){let{brands:e,commerceOnly:t,domains:i,onSale:r,priceMax:o}=(0,h.b)();return(0,a.jsxs)(n.kC,{alignItems:"center",direction:"column",gap:4,justifyContent:"center",children:[(0,a.jsxs)(n.kC,{gap:2,wrap:!0,children:[r&&(0,a.jsx)(c,{}),o&&(0,a.jsx)(u,{}),e&&(0,a.jsx)(s,{}),i&&(0,a.jsx)(d,{})]}),t&&(0,a.jsx)(p,{})]})}},50245:(e,t,i)=>{i.d(t,{Z:()=>l});var n=i(616550),r=i(835599),o=i(623891);function l(){let e=(0,n.TH)(),t=(0,n.k6)();return function(i){let n=(0,o.Z)();n.filter_location=i,t.replace((0,r.Z)(e.pathname,n))}}},43796:(e,t,i)=>{i.d(t,{Z:()=>c,q:()=>d});var n=i(616550),r=i(340523),o=i(447479),l=i(782005),a=i(835599),s=i(623891);let d=["brands","colors","commerce_only","domains","on_sale","price_max","price_min","style"];function c(){let e=(0,n.k6)(),t=(0,n.TH)(),{checkExperiment:i}=(0,r.F)(),{scope:c}=(0,n.UO)();return function(n){let r=(0,s.Z)();r.rs=o.i.SHOPPING_FILTER,n.forEach(({key:e,value:t})=>{""!==t?r[e]=t:delete r[e]}),(i("web_hundred_percent_product_load",{dangerouslySkipActivation:!0}).anyEnabled||i("hundred_percent_product_load_i8n",{dangerouslySkipActivation:!0}).anyEnabled)&&c!==l.lw.PINS&&!d.some(e=>"commerce_only"!==e&&e in r)&&delete r.commerce_only,e.push((0,a.Z)(t.pathname,r))}}},537850:(e,t,i)=>{i.d(t,{Z:()=>p});var n=i(295977),r=i(684851),o=i(730773),l=i(79589),a=i(72994),s=i(616550),d=i(340523),c=i(624797),u=i(842748);function p(){let e=(0,n.Z)(),t=(0,r.Z)(),i=(0,o.Z)(),p=(0,l.Z)(),h=(0,a.Z)(),_=function(){let{checkExperiment:e}=(0,d.F)(),t=(0,s.TH)(),{commerce_only:i}=(0,c.mB)(t.search);return!!i&&(!!e("web_hundred_percent_product_load",{dangerouslySkipActivation:!0}).anyEnabled||!!e("hundred_percent_product_load_i8n",{dangerouslySkipActivation:!0}).anyEnabled)}(),x=(0,u.Z)();return e||t||i||p||h||_||x}},279912:(e,t,i)=>{i.d(t,{O:()=>m,Z:()=>v});var n=i(667294),r=i(883119),o=i(590919),l=i(214877),a=i(140017),s=i(406893),d=i(614205),c=i(20350),u=i(785893);function p({active:e,hovered:t,onBlur:i,onFocus:p,onMouseDown:h,onMouseEnter:_,onMouseLeave:x,onMouseUp:y,auxData:g,componentType:v,imageHeight:f,story:j,viewParameter:b,viewType:w}){let{logContextEvent:S}=(0,l.v)(),P=(0,a.ZP)(),I=(0,n.useRef)(null),[k,E]=(0,n.useState)(!1);if(!j)return null;let Z=j.title?.format||P.bt("Shop the Look", "Shop the look", "ShoppingModulePopover.Popover.Header", undefined, true),C=j.display_options?.content_display?.component_type,T={...g,pin_id:j.closeup_id,story_id:j.id};return(0,u.jsxs)(n.Fragment,{children:[(0,u.jsx)(r.xu,{dangerouslySetInlineStyle:{__style:{top:`${f-48-16}px`,userSelect:"none"}},left:!0,margin:"auto",position:"absolute",right:!0,width:"fit-content",children:(0,u.jsx)(r.iP,{onBlur:i,onFocus:p,onKeyDown:h,onMouseDown:h,onMouseEnter:_,onMouseLeave:x,onMouseUp:y,onTap:()=>{E(!k),S({aux_data:T,component:v,element:13841,event_type:101,object_id_str:j.id,view_parameter:b,view_type:w}),S({aux_data:T,component:C,event_type:13,object_id_str:j.id,view_parameter:b,view_type:w})},children:(0,u.jsxs)(r.xu,{ref:I,alignItems:"center",color:e||t?"secondary":"default",dangerouslySetInlineStyle:{__style:{paddingRight:"16px"}},direction:"row",display:"flex",justifyContent:"center",padding:1,rounding:3,children:[(0,u.jsx)(r.xu,{direction:"row",display:"flex",marginEnd:2,children:(0,u.jsx)(c.Z,{imageOverlapMargin:-4,storyKey:{type:"deprecated",data:j}})}),(0,u.jsx)(r.xu,{children:(0,u.jsx)(r.JO,{accessibilityLabel:P.bt("Descubra produtos para compor um estilo com este look.", "Discover products to style with this look.", "ShoppingModulePopover.DropdownIcon", undefined, true),color:"default",icon:"arrow-down",size:12})})]})})}),k&&(0,u.jsxs)(r.mh,{zIndex:d.k,children:[(0,u.jsx)(s.Z,{unsafeCSS:'div[id="shopTheLookPopover"] { border: unset }'}),(0,u.jsxs)(r.J2,{__overflow:"hidden",accessibilityLabel:P.bt("Uma seleção de Pins de produto para compor um estilo com este look.", "A selection of product Pins to style with this look.", "ShoppingModulePopover.Popover", undefined, true),anchor:I.current,id:"shopTheLookPopover",idealDirection:"down",onDismiss:()=>{E(!1),S({aux_data:T,component:C,event_type:123,object_id_str:j.id,view_parameter:b,view_type:w})},role:"menu",size:396,children:[(0,u.jsx)(r.xu,{alignItems:"center",display:"flex",height:64,justifyContent:"center",padding:2,children:(0,u.jsx)(r.X6,{size:"300",children:Z})}),(0,u.jsx)(r.xu,{marginBottom:0,children:(0,u.jsx)(o.Z,{auxData:g,carouselSlidersContextLogData:{...T,objectIdStr:j.id},disableHeader:!0,enablePageScrollOverride:!0,gutterWidth:8,itemWidth:148,itemWidthHeightRatio:m,saveButtonOptions:{type:"inline",hidePinBetterSaveDropdown:!0},slotIndex:0,story:j,styleOverrides:{carouselContainerMarginBottom:0,carouselPaddingX:8,navigationFabOpacity:1,navigationFabSize:32,showModuleBorder:!1},surface:"VisualInspirationShoppingPin",viewParameter:b,viewType:w,width:396})})]})]})]})}var h=i(494125);let _=`
  .fade1 {
    animation: fadeOutThenAppear1 0.6s linear forwards;
  }

  .fade2 {
    animation: fadeOutThenAppear2 0.6s linear forwards;
  }

  @keyframes fadeOutThenAppear1 {
    0% {
      opacity: 1;
    }
    25% {
      opacity: 0;
    }
    75% {
      opacity: 0;
    }
    100% {
      opacity: 1;
    }
  }

  @keyframes fadeOutThenAppear2 {
    0% {
      opacity: 1;
    }
    25% {
      opacity: 0;
    }
    75% {
      opacity: 0;
    }
    100% {
      opacity: 1;
    }
  }
`;var x=i(213377);function y({auxData:e,sceneCarouselRef:t,stories:i,storyIndex:a,viewParameter:d,viewType:c}){let[p,y]=(0,n.useState)(Array(i.length).fill(0)),{animationCSS:g,carouselRef:v,carouselSlideTransitionRef:f,delayedData:j}=function({auxData:e,componentType:t,data:i,triggeringCarouselRef:r,viewParameter:o,viewType:a}){let s=(0,n.useRef)(null),d=(0,n.useRef)(!0),c=(0,n.useRef)(null),[u,p]=(0,n.useState)(i),{logContextEvent:x}=(0,l.v)();return(0,n.useEffect)(()=>{let e=setTimeout(()=>{p(i)},150);return()=>clearTimeout(e)},[p,i]),(0,h.Z)(()=>{let i=r.current?.querySelector('div[data-test-id="carousel-slider-left"]'),n=r.current?.querySelector('div[data-test-id="carousel-slider-right"]'),l=s.current,u=()=>c.current?clearTimeout(c.current):void 0,p=()=>{d.current=!1,u(),c.current=setTimeout(()=>{d.current=!0},600),l?.classList.contains("fade1")?(l?.classList.remove("fade1"),l?.classList.add("fade2")):(l?.classList.remove("fade2"),l?.classList.add("fade1")),x({aux_data:e,component:t,event_type:81,view_parameter:o,view_type:a})};return i&&n&&l&&(i.addEventListener("click",p),n.addEventListener("click",p)),()=>{i&&n&&l&&(i.removeEventListener("click",p),n.removeEventListener("click",p)),u()}}),{animationCSS:_,carouselRef:s,carouselSlideTransitionRef:d,delayedData:u}}({auxData:e,componentType:i[0].display_options?.content_display?.component_type,data:a,triggeringCarouselRef:t,viewParameter:d,viewType:c}),b=i[j],w=p[j],S={...e,pin_id:b.closeup_id,story_id:b.id};return(0,u.jsxs)(n.Fragment,{children:[(0,u.jsx)(s.Z,{unsafeCSS:g}),(0,u.jsx)(r.xu,{ref:v,marginTop:2,children:(0,u.jsx)(o.Z,{auxData:e,carouselSlidersContextLogData:{...S,objectIdStr:b.id},disableHeader:!0,disableTransition:!f.current,enablePageScrollOverride:!0,gutterWidth:8,itemWidth:124,itemWidthHeightRatio:m,saveButtonOptions:{type:"inline",hidePinBetterSaveDropdown:!0},setSlideIndexOverride:e=>{y(t=>t.map((t,i)=>a===i?e:t))},slideIndexOverride:w,slotIndex:0,story:b,styleOverrides:{carouselContainerMarginBottom:0,carouselPaddingX:16,justifyContent:"start",navigationFabOpacity:1,navigationFabSize:32,showModuleBorder:!1},surface:"VisualInspirationShoppingPin",viewParameter:d,viewType:c,width:x.fu-2*x.Ke})})]})}var g=i(340523);let m=1;function v({auxData:e,slotIndex:t,story:i,viewParameter:l,viewType:a}){let{checkExperiment:s}=(0,g.F)(),d=(0,n.useRef)(null),{anyEnabled:c,group:h}=s("web_see_it_style",{dangerouslySkipActivation:!0}),{anyEnabled:_,group:m}=s("search_ways_to_style_it_experiment",{dangerouslySkipActivation:!0}),v=3===a,f=(h.startsWith("enabled_dropdown")||"employees"===h)&&v||(m.startsWith("enabled_dropdown")||"employees"===m)&&!v,j=i.objects?.filter(e=>"pin"===e.type),b={...i,objects:j},w=i.objects?.flatMap(e=>"story"===e.type?[e]:[]);if(!(c||_)||!j||!j.length)return null;let S=f?201:256,P=1.38*S,I=f?16:x.fu/2-S/2-x.Ke,k=i.display_options?.content_display?.component_type,E=i.objects?.map(({type:e,id:t})=>`${e}:${t}`).join("|"),Z={...e,story_id:i.id},C=null,T=null;if(w&&w.length>0){if(f){let t=({productStory:t,index:i,...n})=>(0,u.jsx)(p,{auxData:e,componentType:k,imageHeight:P,story:t,viewParameter:l,viewType:a,...n},`${t.closeup_id||i}-WaysToStylePopover`);C=w?.map((e,i)=>n=>t({productStory:e,index:i,...n}))}else T=t=>(0,u.jsx)(y,{auxData:e,sceneCarouselRef:d,stories:w,storyIndex:t,viewParameter:l,viewType:a})}return(0,u.jsx)(r.xu,{ref:d,children:(0,u.jsx)(o.Z,{auxData:e,carouselSlidersContextLogData:{...Z,objectIdStr:i.id},contentIds:E,enablePageScrollOverride:f,gutterWidth:8,initialSlideIndex:f?0:1,itemWidth:S,itemWidthHeightRatio:1.38,rednerFooterModule:T,resolution:"high-res",slideOverlays:C,slotIndex:t,story:b,styleOverrides:{carouselContainerMarginBottom:f?4:0,carouselPaddingX:I,headerMarginTop:4,headerMarginX:4,navigationFabOpacity:1,navigationFabSize:32,showModuleBorder:!0,showExtraSmallSubtitle:!0},surface:f?"VisualInspirationPin":"VisualInspirationFocusPin",viewParameter:l,viewType:a,width:"100%"})})}},249150:(e,t,i)=>{i.d(t,{Z:()=>_});var n=i(667294),r=i(883119),o=i(76561),l=i(785893);class a extends n.Component{renderPulsar(){let{anchor:e,handleComplete:t,handlePulsarCompleteOnHover:i,zIndex:n}=this.props;return(0,l.jsx)(o.Z,{anchor:e,onMouseEnter:i,onTouch:t,zIndex:n})}renderFlyout(){let{anchor:e,tooltip:t,handleDismiss:i,handleComplete:n}=this.props;if(!t)return null;let{cancelButtonText:o,confirmButtonText:a,mainText:s,idealDirection:d="down"}=t,c=o&&!!i&&a&&n;return(0,l.jsx)(r.Li,{anchor:e,idealDirection:d,message:s,onDismiss:i,primaryAction:{onClick:c?i:n,text:c?String(o):String(a),role:"button"},size:"flexible"})}render(){let{anchor:e,pulserOnly:t}=this.props;return e?t?this.renderPulsar():this.renderFlyout():null}}var s=i(703404),d=i(839391),c=i(256683),u=i(325362);let p=({anchor:e,anchorExperiences:t,passedExperience:i})=>i||(t?t[e]:null),h=e=>{let{display_data:t}=e;return t.tooltip&&(t.tooltip={...t.tooltip.options,...t.tooltip},delete t.tooltip.options),(0,c.Z)(u.Z,!0)(t)};function _({anchor:e,anchorElementRef:t,children:i,containerBoxConfig:o,experience:c,isHidden:u,onCompleteClick:_,zIndex:x}){let{completeExperience:y,dismissExperience:g,experiences:m,viewExperience:v}=(0,d.Z)(),f=p({anchor:e,anchorExperiences:Object.values(m).reduce((e,t)=>(8===t.type&&(e[(0,s.A0)(t)]=t),e),{}),passedExperience:c}),j=f?.display_data?.delay||0,[b,w]=(0,n.useState)(!!j);if((0,n.useEffect)(()=>{if(j>0&&b){let e=setTimeout(()=>{w(!1)});return()=>clearTimeout(e)}return()=>{}},[j,b]),(0,n.useEffect)(()=>{!b&&f&&v(f.placement_id,f.experience_id)},[b,f]),!f||b||u)return n.Children.only(i);let S=h(f),P=()=>{f.display_data?.complete_on_hover&&y(f.placement_id,f.experience_id)};return(0,l.jsxs)(r.xu,{display:o?.display,height:o?.height,position:"relative",children:[(0,l.jsx)(r.iP,{onMouseEnter:P,onTap:()=>{_&&_(),S.skipComplete||y(f.placement_id,f.experience_id)},children:n.Children.only(i)}),(0,l.jsx)(a,{anchor:t||null,handleComplete:()=>{t instanceof HTMLElement&&t.click()},handleDismiss:e=>{e?.event&&e.event.stopPropagation(),g(f.placement_id,f.experience_id)},handlePulsarCompleteOnHover:P,pulserOnly:!!S.pulserOnly,tooltip:S.tooltip,zIndex:x})]})}},172203:(e,t,i)=>{i.d(t,{Z:()=>p});var n=i(667294),r=i(545007),o=i(442279),l=i(839391),a=i(5859),s=i(953565);let d=(0,o.P1)(e=>e.experiences,(e,t)=>t,(e,t)=>e[t]),c=(e,t,i={})=>(0,s.nP)(`${e}.${t}`,{sampleRate:1,tags:i}),u=(e,t)=>"function"==typeof t?t(e):t,p=(e,t={},i=!1)=>{let[o,s]=(0,n.useReducer)(u,t),{isBot:p}=(0,a.B)(),{fetchExperienceForPlacements:h,mountPlacement:_,triggerExperimentsForPlacement:x,unmountPlacement:y}=(0,l.Z)();(0,n.useDebugValue)(`Placement Hook ID - ${e}`),(0,n.useEffect)(()=>{let t={...o},n=i&&t?.advertiser_id?{advertiserId:t.advertiser_id}:void 0;return _(e,t,n),()=>{y(e)}},[]),(0,n.useEffect)(()=>{Object.keys(o).length>0&&h([e],p,o)},[o]);let g=(0,r.v9)(t=>d(t,e)),m=(0,r.v9)(t=>t.experiencesMulti[e]),v=g?g.triggerable_placed_exps:[];return(0,n.useEffect)(()=>{c("experienceservice","placementHookExperimentTrigger.1",{platform:"web",placement_id:e,...v}),x(e,o)},[JSON.stringify(v)]),{experience:g,experiencesMulti:m,setExtraContext:s}}},888973:(e,t,i)=>{i.d(t,{Z:()=>r});let n=["orig","736x","564x","474x","236x","170x"],r=({imageSizeToImageMap:e,preferredSize:t})=>{let i=e[t];if(i)return{height:i.height,url:i.url,width:i.width};let r=n.indexOf(t);if(r>=0)for(let t=r+1;t<n.length;t+=1){let i=e[n[t]];if(i)return{height:i.height,url:i.url,width:i.width}}return{height:e["236x"]?.height,url:e["236x"]?.url,width:e["236x"]?.width}}},835599:(e,t,i)=>{i.d(t,{Z:()=>n});let n=(e,t)=>{let i=new URL(e,"https://pinterest.com");return i.search=new URLSearchParams(t).toString(),i.toString().substring(i.origin.length)}},587070:(e,t,i)=>{i.d(t,{Z:()=>r});var n=i(667294);function r(e,t){let i=(0,n.useRef)([]),[r,o]=(0,n.useState)(),[l,a]=(0,n.useReducer)(r??(()=>t),t),s=(0,n.useCallback)(t=>{r?a(t):(i.current.length||e().then(e=>{o(()=>e.default)}),i.current=[...i.current,t])},[e,r]);return(0,n.useEffect)(()=>{r&&(i.current.forEach(a),i.current=[])},[r]),[l,s]}},20350:(e,t,i)=>{i.d(t,{Z:()=>c,j:()=>s}),i(167912);var n,r=i(883119),o=i(696534),l=i(54977),a=i(785893);let s=40,d=void 0!==n?n:n=i(385973);function c({imageOverlapMargin:e=0,storyKey:t}){let i=(0,l.Z)(d,t),n=(i?.objects??[]).flatMap(e=>(!e.__typename||"Pin"===e.__typename)&&e.imageSpec_236x?.url?e.imageSpec_236x.url:[]).slice(0,3);return 0===n.length?null:n.map((t,i)=>(0,a.jsx)(r.xu,{color:"default",dangerouslySetInlineStyle:{__style:{border:`1px solid ${(0,o.Yc)()?"black":"white"}`,borderRadius:"9px"}},marginEnd:i===n.length-1?0:e,zIndex:new r.Ry(i),children:(0,a.jsx)(r.zd,{height:38,rounding:2,wash:!0,width:38,children:(0,a.jsx)(r.Ee,{alt:"",fit:"cover",naturalHeight:1,naturalWidth:1,role:"presentation",src:t})})},t))}},451102:(e,t,i)=>{i.d(t,{Z:()=>o});var n=i(883119),r=i(785893);function o({children:e,color:t,isDarkMode:i,outlined:o,type:l="bold",rounding:a=4}){return(0,r.jsxs)(n.xu,{position:"relative",children:[(0,r.jsx)(n.xu,{dangerouslySetInlineStyle:{__style:{WebkitMaskImage:"-webkit-radial-gradient(white, black)"}},"data-test-id":"outline-content",overflow:"hidden",rounding:a,children:e}),o&&(0,r.jsx)(n.xu,{bottom:!0,color:"transparent",dangerouslySetInlineStyle:{__style:function({color:e,isDarkMode:t,type:i}){let n=t?"#fff":"#000",r=t?"#000":"#fff";return"solid"===i?{boxShadow:`inset 0 0 0 2px ${e??n}`,WebkitBoxShadow:`inset 0 0 0 2px ${e??n}`,MozBoxShadow:`inset 0 0 0 2px ${e??n}`}:{boxShadow:`inset 0 0 0 2px ${e??n}, inset 0 0 0 4px ${r}`,WebkitBoxShadow:`inset 0 0 0 2px ${e??n}, inset 0 0 0 4px ${r}`,MozBoxShadow:`inset 0 0 0 2px ${e??n}, inset 0 0 0 4px ${r}`}}({color:t,isDarkMode:i,type:l})},"data-test-id":"outline-box",left:!0,position:"absolute",right:!0,rounding:a,top:!0})]})}},614205:(e,t,i)=>{i.d(t,{k:()=>n});let n=new(i(883119)).Ry(700)},768735:(e,t,i)=>{function n(e,t){return{type:"SEARCH_PIN_CLOSEUP_VIEWED",payload:{pinId:e,query:t}}}function r(e){return{type:"SEARCH_QUERY_STARTED",payload:{query:e}}}function o(e){return{type:"SEARCH_QUERY_INVALIDATED",payload:{query:e}}}i.d(t,{Y4:()=>n,g4:()=>r,sb:()=>o})}}]);
//# sourceMappingURL=https://sm.pinimg.com/webapp/65634.pt_BR-855241ce6119503a.mjs.map