const getProductsById = async(productId : string) => {
    try {
      let res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/products/productPage?productId=${productId}`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
      let products = await res.json();
      console.log(products)
      return products;
    } catch (e) {
      console.error(e);
    }
  }

export default getProductsById;