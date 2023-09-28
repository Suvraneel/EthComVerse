const getProducts = async() => {
    try {
      let res = await fetch(`http://localhost:3000/api/products`, {
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