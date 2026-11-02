// Observe one real service response without relying on Chromium retaining its
// network-inspector response body after the UI starts another request.
export async function wireResponse(page, target, action, actual, label) {
  let resolve, reject;
  const observed = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  const timeout = setTimeout(
    () => reject(new Error("native browser response was not observed")),
    15000,
  );
  const handler = async (route) => {
    try {
      const result = await actual(route, label, target);
      await route.fulfill({
        status: result.status,
        contentType: "application/json",
        body: result.body,
      });
      resolve(JSON.parse(result.body));
    } catch (error) {
      reject(error);
      await route.abort("failed").catch(() => {});
    }
  };
  await page.route(target, handler, { times: 1 });
  try {
    const [result] = await Promise.all([observed, action()]);
    return result;
  } finally {
    clearTimeout(timeout);
    await page.unroute(target, handler);
  }
}
