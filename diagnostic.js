// CORS and Connectivity Diagnostic Test
// Run this in browser console at http://localhost:5174

(async () => {
  console.log("🔍 SecureMail Network Diagnostic");
  console.log("================================\n");
  
  const tests = [];
  
  // Test 1: Basic HEAD request
  console.log("Test 1️⃣  - Basic HEAD request to backend...");
  try {
    const response = await fetch("http://localhost:8080/health", { method: "HEAD" });
    console.log("✅ Test 1 passed:", response.status, response.statusText);
    tests.push({ name: "HEAD /health", status: "✅ PASS" });
  } catch (error) {
    console.error("❌ Test 1 failed:", error);
    tests.push({ name: "HEAD /health", status: "❌ FAIL", error: String(error) });
  }
  
  // Test 2: GET /health
  console.log("\nTest 2️⃣  - GET /health...");
  try {
    const response = await fetch("http://localhost:8080/health");
    const data = await response.json();
    console.log("✅ Test 2 passed:", data);
    tests.push({ name: "GET /health", status: "✅ PASS" });
  } catch (error) {
    console.error("❌ Test 2 failed:", error);
    tests.push({ name: "GET /health", status: "❌ FAIL", error: String(error) });
  }
  
  // Test 3: OPTIONS preflight for POST
  console.log("\nTest 3️⃣  - OPTIONS preflight for POST /api/v1/scan-upload...");
  try {
    const response = await fetch("http://localhost:8080/api/v1/scan-upload", {
      method: "OPTIONS",
      headers: {
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
      },
    });
    console.log("✅ Test 3 passed:", response.status);
    console.log("   CORS headers:");
    console.log("   - Access-Control-Allow-Origin:", response.headers.get("Access-Control-Allow-Origin"));
    console.log("   - Access-Control-Allow-Methods:", response.headers.get("Access-Control-Allow-Methods"));
    console.log("   - Access-Control-Allow-Headers:", response.headers.get("Access-Control-Allow-Headers"));
    tests.push({ name: "OPTIONS preflight", status: "✅ PASS" });
  } catch (error) {
    console.error("❌ Test 3 failed:", error);
    tests.push({ name: "OPTIONS preflight", status: "❌ FAIL", error: String(error) });
  }
  
  // Test 4: Empty POST request
  console.log("\nTest 4️⃣  - Empty POST to /api/v1/scan-upload...");
  try {
    const response = await fetch("http://localhost:8080/api/v1/scan-upload", {
      method: "POST",
    });
    console.log("✅ Test 4 response:", response.status);
    const text = await response.text();
    console.log("   Body:", text.substring(0, 200));
    tests.push({ name: "Empty POST", status: "✅ RECEIVED", statusCode: response.status });
  } catch (error) {
    console.error("❌ Test 4 failed:", error);
    tests.push({ name: "Empty POST", status: "❌ FAIL", error: String(error) });
  }
  
  // Test 5: POST with FormData (no file)
  console.log("\nTest 5️⃣  - POST with empty FormData...");
  try {
    const formData = new FormData();
    formData.append("user_accepts_danger", "false");
    
    const response = await fetch("http://localhost:8080/api/v1/scan-upload", {
      method: "POST",
      body: formData,
    });
    console.log("✅ Test 5 response:", response.status);
    const text = await response.text();
    console.log("   Body:", text.substring(0, 200));
    tests.push({ name: "FormData POST", status: "✅ RECEIVED", statusCode: response.status });
  } catch (error) {
    console.error("❌ Test 5 failed:", error);
    tests.push({ name: "FormData POST", status: "❌ FAIL", error: String(error) });
  }
  
  // Summary
  console.log("\n📋 Test Summary:");
  console.log("================================");
  tests.forEach((t, i) => {
    console.log(`${i+1}. ${t.name}: ${t.status}`);
    if (t.error) console.log(`   Error: ${t.error}`);
  });
  
  const passed = tests.filter(t => t.status.includes("✅")).length;
  console.log(`\nResult: ${passed}/${tests.length} tests passed`);
  
})();
