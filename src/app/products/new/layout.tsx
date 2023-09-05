
type Product = () => {
    title: string;
    description: string;
    category: string;
    price: number;
    file: string;
    tags: string[];
};

const Layout = ({
    children,
}: {
    children: React.ReactNode
}) => {
    return (
        <div>
            {children}
        </div>
    )
}

export default Layout;