import { hashFileSlices } from "./crypto";

self.onmessage = async (event: MessageEvent<unknown>) => {
  if (!(event.data instanceof File) || event.data.size > 1073741824) {
    self.postMessage({ error: true });
    return;
  }
  self.onmessage = null;
  const file = event.data;
  try {
    const digest = await hashFileSlices(file, (progress) =>
      self.postMessage({ progress }),
    );
    self.postMessage({ digest });
  } catch {
    self.postMessage({ error: true });
  }
};
