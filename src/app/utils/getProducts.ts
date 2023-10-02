const getProducts = async() => {
    try {
      let res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/products`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
      let products = await res.json();
      console.log("Fetched Products")
      return products.products;
    } catch (e) {
      console.error(e);
    }
  }

export default getProducts;