const createProduct = async (productData: any) => {
    try {
      let res = await fetch(`http://localhost:3000/api/products`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(productData), // Replace productData with the data you want to send
      });
  
      if (!res.ok) {
        throw new Error(`Failed to create product: ${res.status}`);
      }
  
      let createdProduct = await res.json();
      console.log("Created Product:", createdProduct);
      return createdProduct;
    } catch (e) {
      console.error(e);
    }
  };
  
  export default createProduct;
  