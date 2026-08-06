export default {
  async fetch() {
    return new Response("synthetic legacy fixture");
  },
  async queue() {},
  async scheduled() {},
};
