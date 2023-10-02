import getProductsById from '@utils/getProductById';
import Exhibit from './Exhibit';

interface IParams {
    productId?: string;
}

const ProductPage = async({
    params,
    searchParams,
  }: {
    params: { slug: string }
    searchParams: { productId: string}
  }) => {
    console.log(searchParams);
    const payload = await getProductsById(searchParams.productId);
    const productsData = payload.product;
    return (
        <Exhibit productsData={productsData}/>
    )
}

export default ProductPage;