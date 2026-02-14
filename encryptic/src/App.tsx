import { Link, Routes, Route } from "react-router-dom";

function Home() {
  return <h1>Home Page</h1>;
}

function Keygen() {
  return <h1>Keygen Page</h1>;
}

export default function App() {
  return (
    <div style={{ padding: 20 }}>
      <nav style={{ display: "flex", gap: 10 }}>
        <Link to="/">Home</Link>
        <Link to="/keygen">Keygen</Link>
      </nav>

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/keygen" element={<Keygen />} />
      </Routes>
    </div>
  );
}
