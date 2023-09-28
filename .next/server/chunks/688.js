exports.id = 688;
exports.ids = [688];
exports.modules = {

/***/ 86023:
/***/ ((__unused_webpack_module, __unused_webpack_exports, __webpack_require__) => {

Promise.resolve(/* import() eager */).then(__webpack_require__.t.bind(__webpack_require__, 31232, 23));
Promise.resolve(/* import() eager */).then(__webpack_require__.t.bind(__webpack_require__, 52987, 23));
Promise.resolve(/* import() eager */).then(__webpack_require__.t.bind(__webpack_require__, 50831, 23));
Promise.resolve(/* import() eager */).then(__webpack_require__.t.bind(__webpack_require__, 56926, 23));
Promise.resolve(/* import() eager */).then(__webpack_require__.t.bind(__webpack_require__, 44282, 23));
Promise.resolve(/* import() eager */).then(__webpack_require__.t.bind(__webpack_require__, 16505, 23))

/***/ }),

/***/ 2504:
/***/ ((__unused_webpack_module, __unused_webpack_exports, __webpack_require__) => {

Promise.resolve(/* import() eager */).then(__webpack_require__.bind(__webpack_require__, 26902))

/***/ }),

/***/ 26902:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  "default": () => (/* binding */ Layout_WalletProvider)
});

// EXTERNAL MODULE: external "next/dist/compiled/react/jsx-runtime"
var jsx_runtime_ = __webpack_require__(56786);
// EXTERNAL MODULE: ./node_modules/next/link.js
var next_link = __webpack_require__(11440);
var link_default = /*#__PURE__*/__webpack_require__.n(next_link);
// EXTERNAL MODULE: external "next/dist/compiled/react"
var react_ = __webpack_require__(18038);
// EXTERNAL MODULE: ./node_modules/connectkit/build/index.es.js + 198 modules
var index_es = __webpack_require__(31498);
// EXTERNAL MODULE: ./node_modules/@headlessui/react/dist/components/dialog/dialog.js + 33 modules
var dialog = __webpack_require__(4184);
// EXTERNAL MODULE: ./node_modules/@headlessui/react/dist/components/transitions/transition.js + 4 modules
var transition = __webpack_require__(82596);
// EXTERNAL MODULE: ./node_modules/next/navigation.js
var navigation = __webpack_require__(57114);
// EXTERNAL MODULE: ./node_modules/@heroicons/react/24/outline/esm/Bars3Icon.js
var Bars3Icon = __webpack_require__(46140);
// EXTERNAL MODULE: ./node_modules/@heroicons/react/24/outline/esm/XMarkIcon.js
var XMarkIcon = __webpack_require__(57048);
;// CONCATENATED MODULE: ./src/components/Layout/HamburgerMenu.tsx
/* __next_internal_client_entry_do_not_use__ default auto */ 







function MobileMenu({ menu }) {
    const pathname = (0,navigation.usePathname)();
    const searchParams = (0,navigation.useSearchParams)();
    const [isOpen, setIsOpen] = (0,react_.useState)(false);
    const openMobileMenu = ()=>setIsOpen(true);
    const closeMobileMenu = ()=>setIsOpen(false);
    (0,react_.useEffect)(()=>{
        const handleResize = ()=>{
            if (window.innerWidth > 768) {
                setIsOpen(false);
            }
        };
        window.addEventListener("resize", handleResize);
        return ()=>window.removeEventListener("resize", handleResize);
    }, [
        isOpen
    ]);
    (0,react_.useEffect)(()=>{
        setIsOpen(false);
    }, [
        pathname,
        searchParams
    ]);
    return /*#__PURE__*/ (0,jsx_runtime_.jsxs)(jsx_runtime_.Fragment, {
        children: [
            /*#__PURE__*/ jsx_runtime_.jsx("button", {
                onClick: openMobileMenu,
                "aria-label": "Open mobile menu",
                className: "flex h-11 w-11 items-center justify-center rounded-md border border-neutral-200 text-black transition-colors dark:border-neutral-700 dark:text-white md:hidden",
                children: /*#__PURE__*/ jsx_runtime_.jsx(Bars3Icon/* default */.Z, {
                    className: "h-4"
                })
            }),
            /*#__PURE__*/ jsx_runtime_.jsx(transition/* Transition */.u, {
                show: isOpen,
                children: /*#__PURE__*/ (0,jsx_runtime_.jsxs)(dialog/* Dialog */.V, {
                    onClose: closeMobileMenu,
                    className: "relative z-50",
                    children: [
                        /*#__PURE__*/ jsx_runtime_.jsx(transition/* Transition */.u.Child, {
                            as: react_.Fragment,
                            enter: "transition-all ease-in-out duration-300",
                            enterFrom: "opacity-0 backdrop-blur-none",
                            enterTo: "opacity-100 backdrop-blur-[.5px]",
                            leave: "transition-all ease-in-out duration-200",
                            leaveFrom: "opacity-100 backdrop-blur-[.5px]",
                            leaveTo: "opacity-0 backdrop-blur-none",
                            children: /*#__PURE__*/ jsx_runtime_.jsx("div", {
                                className: "fixed inset-0 bg-black/30",
                                "aria-hidden": "true"
                            })
                        }),
                        /*#__PURE__*/ jsx_runtime_.jsx(transition/* Transition */.u.Child, {
                            as: react_.Fragment,
                            enter: "transition-all ease-in-out duration-300",
                            enterFrom: "translate-x-[-100%]",
                            enterTo: "translate-x-0",
                            leave: "transition-all ease-in-out duration-200",
                            leaveFrom: "translate-x-0",
                            leaveTo: "translate-x-[-100%]",
                            children: /*#__PURE__*/ jsx_runtime_.jsx(dialog/* Dialog */.V.Panel, {
                                className: "fixed bottom-0 left-0 right-0 top-0 flex h-full w-full flex-col bg-white pb-6 dark:bg-black",
                                children: /*#__PURE__*/ (0,jsx_runtime_.jsxs)("div", {
                                    className: "p-4",
                                    children: [
                                        /*#__PURE__*/ jsx_runtime_.jsx("button", {
                                            className: "mb-4 flex h-11 w-11 items-center justify-center rounded-md border border-neutral-200 text-black transition-colors dark:border-neutral-700 dark:text-white",
                                            onClick: closeMobileMenu,
                                            "aria-label": "Close mobile menu",
                                            children: /*#__PURE__*/ jsx_runtime_.jsx(XMarkIcon/* default */.Z, {
                                                className: "h-6"
                                            })
                                        }),
                                        menu.length ? /*#__PURE__*/ jsx_runtime_.jsx("ul", {
                                            className: "flex w-full flex-col",
                                            children: menu.map((item)=>/*#__PURE__*/ jsx_runtime_.jsx("li", {
                                                    className: "py-2 text-xl text-black transition-colors hover:text-neutral-500 dark:text-white",
                                                    children: /*#__PURE__*/ jsx_runtime_.jsx((link_default()), {
                                                        href: item.path,
                                                        onClick: closeMobileMenu,
                                                        children: item.title
                                                    })
                                                }, item.title))
                                        }) : null
                                    ]
                                })
                            })
                        })
                    ]
                })
            })
        ]
    });
}

;// CONCATENATED MODULE: ./src/components/Layout/Navbar.tsx
/* __next_internal_client_entry_do_not_use__ default auto */ 




const Navbar = ()=>{
    const menu = [
        {
            title: "Home",
            path: "/"
        },
        {
            title: "Discover",
            path: "/discover"
        },
        {
            title: "Products",
            path: "/products"
        }
    ];
    return /*#__PURE__*/ (0,jsx_runtime_.jsxs)("nav", {
        className: "flex items-center justify-between p-4 lg:px-6 sticky top-0 bg-black/70 backdrop-blur-sm z-50",
        children: [
            /*#__PURE__*/ jsx_runtime_.jsx("div", {
                className: "block flex-none md:hidden",
                children: /*#__PURE__*/ jsx_runtime_.jsx(MobileMenu, {
                    menu: menu
                })
            }),
            /*#__PURE__*/ (0,jsx_runtime_.jsxs)("div", {
                className: "flex w-full items-center",
                children: [
                    /*#__PURE__*/ (0,jsx_runtime_.jsxs)("div", {
                        className: "flex w-full md:w-1/3",
                        children: [
                            /*#__PURE__*/ jsx_runtime_.jsx((link_default()), {
                                href: "/",
                                className: "mr-2 flex w-full items-center justify-center md:w-auto lg:mr-6",
                                children: /*#__PURE__*/ jsx_runtime_.jsx("div", {
                                    className: "ml-2 flex-none text-sm font-medium uppercase md:hidden lg:block",
                                    children: "ETHCOMVERSE"
                                })
                            }),
                            menu.length ? /*#__PURE__*/ jsx_runtime_.jsx("ul", {
                                className: "hidden gap-6 text-sm md:flex md:items-center",
                                children: menu.map((item)=>/*#__PURE__*/ jsx_runtime_.jsx("li", {
                                        children: /*#__PURE__*/ jsx_runtime_.jsx((link_default()), {
                                            href: item.path,
                                            className: "text-neutral-500 underline-offset-4 hover:text-black hover:underline dark:text-neutral-400 dark:hover:text-neutral-300",
                                            children: item.title
                                        })
                                    }, item.title))
                            }) : null
                        ]
                    }),
                    /*#__PURE__*/ jsx_runtime_.jsx("div", {
                        className: "hidden justify-center md:flex md:w-1/3"
                    }),
                    /*#__PURE__*/ jsx_runtime_.jsx("div", {
                        className: "flex justify-end md:w-1/3",
                        children: /*#__PURE__*/ jsx_runtime_.jsx(react_.Suspense, {
                            children: /*#__PURE__*/ jsx_runtime_.jsx("div", {
                                className: "w-fit h-fit rounded-lg border border-cardGray-700 hover:border-gray-700 overflow-hidden",
                                children: /*#__PURE__*/ jsx_runtime_.jsx(index_es/* ConnectKitButton */.x3, {})
                            })
                        })
                    })
                ]
            })
        ]
    });
};
/* harmony default export */ const Layout_Navbar = (Navbar);

// EXTERNAL MODULE: ./node_modules/wagmi/dist/index.js + 25 modules
var dist = __webpack_require__(40965);
// EXTERNAL MODULE: ./node_modules/viem/dist/esm/chains/definitions/filecoinCalibration.js
var filecoinCalibration = __webpack_require__(64709);
;// CONCATENATED MODULE: ./src/components/Layout/WalletProvider.tsx
/* __next_internal_client_entry_do_not_use__ default auto */ 





const walletConnectProjectId = process.env.WALLETCONNECT_PROJECT_ID;
// Choose which chains you'd like to show
const chains = [
    filecoinCalibration/* filecoinCalibration */.J
];
const config = (0,dist/* createConfig */._g)((0,index_es/* getDefaultConfig */._K)({
    appName: "EthComVerse",
    walletConnectProjectId,
    chains
}));
const WalletProvider = ({ children })=>{
    return /*#__PURE__*/ jsx_runtime_.jsx(dist/* WagmiConfig */.eM, {
        config: config,
        children: /*#__PURE__*/ (0,jsx_runtime_.jsxs)(index_es/* ConnectKitProvider */.bO, {
            mode: "dark",
            customTheme: customTheme,
            options: {
                embedGoogleFonts: true
            },
            children: [
                /*#__PURE__*/ jsx_runtime_.jsx(Layout_Navbar, {}),
                /*#__PURE__*/ jsx_runtime_.jsx(react_.Suspense, {
                    children: children
                })
            ]
        })
    });
};
/* harmony default export */ const Layout_WalletProvider = (WalletProvider);
const customTheme = {
    "--ck-font-family": "Inter",
    "--ck-font-weight": "400",
    "--ck-border-radius": "20px",
    "--ck-overlay-backdrop-filter": "blur(2px)",
    "--ck-modal-heading-font-weight": "500",
    "--ck-qr-border-radius": "16px",
    "--ck-connectbutton-font-size": "15px",
    "--ck-connectbutton-color": "#ffffff",
    "--ck-connectbutton-background": "#000000",
    "--ck-connectbutton-background-secondary": "#FFFFFF",
    "--ck-connectbutton-border-radius": "5px",
    "--ck-connectbutton-box-shadow": "0px 0px 16px 10px #ffffff00",
    "--ck-connectbutton-hover-color": "#ffffff",
    "--ck-connectbutton-hover-background": "#000000",
    // "--ck-connectbutton-hover-box-shadow": "1px 1px 20px 10px #47a3ff4f",
    "--ck-connectbutton-active-color": "#ffffff",
    "--ck-connectbutton-active-background": "#3f3f3f",
    "--ck-connectbutton-active-box-shadow": "0 0 0 0 #ffffff",
    "--ck-connectbutton-balance-color": "#373737",
    "--ck-connectbutton-balance-background": "#fff",
    "--ck-connectbutton-balance-box-shadow": "inset 0 0 0 1px #F6F7F9",
    "--ck-connectbutton-balance-hover-background": "#F6F7F9",
    "--ck-connectbutton-balance-hover-box-shadow": "inset 0 0 0 1px #F0F2F5",
    "--ck-connectbutton-balance-active-background": "#F0F2F5",
    "--ck-connectbutton-balance-active-box-shadow": "inset 0 0 0 1px #EAECF1",
    "--ck-primary-button-font-weight": "500",
    "--ck-primary-button-border-radius": "16px",
    "--ck-primary-button-color": "#d4d4d4",
    "--ck-primary-button-background": "#000000",
    "--ck-primary-button-box-shadow": "0 0 0 0 #ffffff",
    "--ck-primary-button-hover-color": "#ffffff",
    "--ck-primary-button-hover-background": "#282828",
    "--ck-primary-button-hover-box-shadow": "0 0 0 0 #ffffff",
    "--ck-primary-button-active-color": "#373737",
    "--ck-primary-button-active-background": "#fdfdfd",
    "--ck-primary-button-active-box-shadow": "0 0 0 0 #ffffff",
    "--ck-secondary-button-font-weight": "500",
    "--ck-secondary-button-border-radius": "16px",
    "--ck-secondary-button-color": "#ffffff",
    "--ck-secondary-button-background": "#111111",
    "--ck-secondary-button-box-shadow": "0 0 0 0 #ffffff",
    "--ck-secondary-button-hover-color": "#ffffff",
    "--ck-secondary-button-hover-background": "#161616",
    "--ck-secondary-button-hover-box-shadow": "0 0 0 0 #ffffff",
    "--ck-secondary-button-active-color": "#373737",
    "--ck-secondary-button-active-background": "#121212",
    "--ck-secondary-button-active-box-shadow": "0 0 0 0 #ffffff",
    "--ck-tertiary-button-font-weight": "500",
    "--ck-tertiary-button-border-radius": "16px",
    "--ck-tertiary-button-color": "#ffffff",
    "--ck-tertiary-button-background": "#000000",
    "--ck-tertiary-button-box-shadow": "0 0 0 0 #ffffff",
    "--ck-tertiary-button-hover-color": "#e1e1e1",
    "--ck-tertiary-button-hover-background": "#181818",
    "--ck-tertiary-button-hover-box-shadow": "0 0 0 0 #ffffff",
    "--ck-tertiary-button-active-color": "#373737",
    "--ck-tertiary-button-active-background": "#F6F7F9",
    "--ck-tertiary-button-active-box-shadow": "0 0 0 0 #ffffff",
    "--ck-modal-box-shadow": "0px 2px 4px 0px #00000005",
    "--ck-overlay-background": "#0625572e",
    "--ck-body-color": "#ffffff",
    "--ck-body-color-muted": "#ffffff",
    "--ck-body-color-muted-hover": "#ededed",
    "--ck-body-background": "#000000",
    "--ck-body-background-transparent": "rgba(255,255,255,0)",
    "--ck-body-background-secondary": "#000000",
    "--ck-body-background-secondary-hover-background": "#e0e4eb",
    "--ck-body-background-secondary-hover-outline": "#4282FF",
    "--ck-body-background-tertiary": "#000000",
    "--ck-body-action-color": "#ffffff",
    "--ck-body-divider": "#ffffff",
    "--ck-body-color-danger": "#ff5050",
    "--ck-body-color-valid": "#2cff4c",
    "--ck-siwe-border": "#F0F0F0",
    "--ck-body-disclaimer-background": "#000000",
    "--ck-body-disclaimer-color": "#ffffff",
    "--ck-body-disclaimer-link-color": "#d8d8d8",
    "--ck-body-disclaimer-link-hover-color": "#ffffff",
    "--ck-tooltip-background": "#000000",
    "--ck-tooltip-background-secondary": "#000000",
    "--ck-tooltip-color": "#ffffff",
    "--ck-tooltip-shadow": "0px 2px 10px 0 #00000014",
    "--ck-dropdown-button-color": "#999999",
    "--ck-dropdown-button-box-shadow": "0 0 0 1px rgba(0,0,0,0.01), 0px 0px 7px rgba(0, 0, 0, 0.05)",
    "--ck-dropdown-button-background": "#fff",
    "--ck-dropdown-button-hover-color": "#8B8B8B",
    "--ck-dropdown-button-hover-background": "#F5F7F9",
    "--ck-qr-dot-color": "#ffffff",
    "--ck-qr-background": "#000000",
    "--ck-qr-border-color": "#3f3f3f",
    "--ck-focus-color": "#1A88F8",
    "--ck-spinner-color": "#1A88F8",
    "--ck-copytoclipboard-stroke": "#CCCCCC",
    "--ck-recent-badge-color": "#ffffff",
    "--ck-recent-badge-background": "#000000",
    "--ck-recent-badge-border-radius": "32px"
};


/***/ }),

/***/ 36386:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  "default": () => (/* binding */ layout),
  metadata: () => (/* binding */ metadata)
});

// EXTERNAL MODULE: external "next/dist/compiled/react/jsx-runtime"
var jsx_runtime_ = __webpack_require__(56786);
// EXTERNAL MODULE: ./node_modules/next/dist/build/webpack/loaders/next-flight-loader/module-proxy.js
var module_proxy = __webpack_require__(61363);
;// CONCATENATED MODULE: ./src/components/Layout/WalletProvider.tsx

const proxy = (0,module_proxy.createProxy)(String.raw`C:\Users\Suvraneel\Work\GitHub\EthComVerse\src\components\Layout\WalletProvider.tsx`)

// Accessing the __esModule property and exporting $$typeof are required here.
// The __esModule getter forces the proxy target to create the default export
// and the $$typeof value is for rendering logic to determine if the module
// is a client boundary.
const { __esModule, $$typeof } = proxy;
const __default__ = proxy.default;


/* harmony default export */ const WalletProvider = (__default__);
// EXTERNAL MODULE: ./node_modules/next/font/google/target.css?{"path":"src\\font\\font.ts","import":"Inter","arguments":[{"subsets":["latin"]}],"variableName":"inter"}
var target_path_src_font_font_ts_import_Inter_arguments_subsets_latin_variableName_inter_ = __webpack_require__(36825);
var target_path_src_font_font_ts_import_Inter_arguments_subsets_latin_variableName_inter_default = /*#__PURE__*/__webpack_require__.n(target_path_src_font_font_ts_import_Inter_arguments_subsets_latin_variableName_inter_);
// EXTERNAL MODULE: ./src/app/globals.css
var globals = __webpack_require__(5023);
;// CONCATENATED MODULE: ./src/app/layout.tsx




const metadata = {
    title: "Create Next App",
    description: "Generated by create next app"
};
const RootLayout = ({ children })=>{
    return /*#__PURE__*/ jsx_runtime_.jsx("html", {
        lang: "en",
        children: /*#__PURE__*/ jsx_runtime_.jsx("body", {
            className: `w-full h-full bg-gradient-to-br from-black via-black to-white/10 ${(target_path_src_font_font_ts_import_Inter_arguments_subsets_latin_variableName_inter_default()).className}`,
            children: /*#__PURE__*/ jsx_runtime_.jsx(WalletProvider, {
                children: children
            })
        })
    });
};
/* harmony default export */ const layout = (RootLayout);


/***/ }),

/***/ 73881:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var next_dist_lib_metadata_get_metadata_route__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(80085);
/* harmony import */ var next_dist_lib_metadata_get_metadata_route__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(next_dist_lib_metadata_get_metadata_route__WEBPACK_IMPORTED_MODULE_0__);
  

  /* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = ((props) => {
    const imageData = {"type":"image/x-icon","sizes":"16x16"}
    const imageUrl = (0,next_dist_lib_metadata_get_metadata_route__WEBPACK_IMPORTED_MODULE_0__.fillMetadataSegment)(".", props.params, "favicon.ico")

    return [{
      ...imageData,
      url: imageUrl + "",
    }]
  });

/***/ }),

/***/ 5023:
/***/ (() => {



/***/ })

};
;