"use strict";
(() => {
var exports = {};
exports.id = 684;
exports.ids = [684];
exports.modules = {

/***/ 38013:
/***/ ((module) => {

module.exports = require("mongodb");

/***/ }),

/***/ 22037:
/***/ ((module) => {

module.exports = require("os");

/***/ }),

/***/ 45092:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  headerHooks: () => (/* binding */ headerHooks),
  originalPathname: () => (/* binding */ originalPathname),
  requestAsyncStorage: () => (/* binding */ requestAsyncStorage),
  routeModule: () => (/* binding */ routeModule),
  serverHooks: () => (/* binding */ serverHooks),
  staticGenerationAsyncStorage: () => (/* binding */ staticGenerationAsyncStorage),
  staticGenerationBailout: () => (/* binding */ staticGenerationBailout)
});

// NAMESPACE OBJECT: ./src/app/api/products/route.ts
var route_namespaceObject = {};
__webpack_require__.r(route_namespaceObject);
__webpack_require__.d(route_namespaceObject, {
  GET: () => (GET),
  POST: () => (POST)
});

// EXTERNAL MODULE: ./node_modules/next/dist/server/node-polyfill-headers.js
var node_polyfill_headers = __webpack_require__(42394);
// EXTERNAL MODULE: ./node_modules/next/dist/server/future/route-modules/app-route/module.js
var app_route_module = __webpack_require__(69692);
// EXTERNAL MODULE: ./node_modules/next/dist/server/future/route-kind.js
var route_kind = __webpack_require__(19513);
// EXTERNAL MODULE: ./src/lib/mongodb.ts
var mongodb = __webpack_require__(54066);
// EXTERNAL MODULE: ./node_modules/next/dist/server/web/exports/next-response.js
var next_response = __webpack_require__(89335);
;// CONCATENATED MODULE: ./src/app/api/products/route.ts


async function GET() {
    try {
        const client = await mongodb/* default */.Z;
        const db = client.db("gumroad");
        const products = await db.collection("products").find({}).sort({
            createdAt: -1
        }).toArray();
        return next_response/* default */.Z.json({
            products
        });
    } catch (error) {
        console.error("Error fetching data from MongoDB:", error);
        return next_response/* default */.Z.json({
            error: "..."
        }, {
            status: 500
        });
    }
}
async function POST(req) {
    try {
        const client = await mongodb/* default */.Z;
        const db = client.db("gumroad");
        const bodyObject = await req.json();
        await db.collection("products").insertOne(bodyObject);
        // console.log(body);
        return next_response/* default */.Z.json({
            status: 200,
            data: bodyObject
        });
    } catch (error) {
        console.error("Error fetching data from MongoDB:", error);
        return next_response/* default */.Z.json({
            error: "..."
        }, {
            status: 500
        });
    }
}

;// CONCATENATED MODULE: ./node_modules/next/dist/build/webpack/loaders/next-app-loader.js?page=%2Fapi%2Fproducts%2Froute&name=app%2Fapi%2Fproducts%2Froute&pagePath=private-next-app-dir%2Fapi%2Fproducts%2Froute.ts&appDir=C%3A%5CUsers%5CSuvraneel%5CWork%5CGitHub%5CEthComVerse%5Csrc%5Capp&appPaths=%2Fapi%2Fproducts%2Froute&pageExtensions=tsx&pageExtensions=ts&pageExtensions=jsx&pageExtensions=js&basePath=&assetPrefix=&nextConfigOutput=&preferredRegion=&middlewareConfig=e30%3D!

// @ts-ignore this need to be imported from next/dist to be external


// @ts-expect-error - replaced by webpack/turbopack loader

const AppRouteRouteModule = app_route_module.AppRouteRouteModule;
// We inject the nextConfigOutput here so that we can use them in the route
// module.
const nextConfigOutput = ""
const routeModule = new AppRouteRouteModule({
    definition: {
        kind: route_kind.RouteKind.APP_ROUTE,
        page: "/api/products/route",
        pathname: "/api/products",
        filename: "route",
        bundlePath: "app/api/products/route"
    },
    resolvedPagePath: "C:\\Users\\Suvraneel\\Work\\GitHub\\EthComVerse\\src\\app\\api\\products\\route.ts",
    nextConfigOutput,
    userland: route_namespaceObject
});
// Pull out the exports that we need to expose from the module. This should
// be eliminated when we've moved the other routes to the new format. These
// are used to hook into the route.
const { requestAsyncStorage , staticGenerationAsyncStorage , serverHooks , headerHooks , staticGenerationBailout  } = routeModule;
const originalPathname = "/api/products/route";


//# sourceMappingURL=app-route.js.map

/***/ })

};
;

// load runtime
var __webpack_require__ = require("../../../webpack-runtime.js");
__webpack_require__.C(exports);
var __webpack_exec__ = (moduleId) => (__webpack_require__(__webpack_require__.s = moduleId))
var __webpack_exports__ = __webpack_require__.X(0, [587,501,335,66], () => (__webpack_exec__(45092)));
module.exports = __webpack_exports__;

})();