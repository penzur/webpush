const stoa = (s) => {
  const padding = '='.repeat((4 - s.length % 4) % 4);
  const base64 = (s + padding)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }

  return outputArray;
};

const endpoint = 'http://localhost:3000';

const opts = {
  userVisibleOnly: true,
  applicationServerKey: ''
};

(async () => {
  try {
    const sw = await navigator.serviceWorker.register('/js/sw.js');

    const { data, status } = await axios.get(endpoint);
    if (status !== 200) return;
    opts.applicationServerKey = stoa(data);

    let subscription = await sw.pushManager.getSubscription();
    if (!subscription) {
      console.log('subscribing...');
      subscription = await sw.pushManager.subscribe(opts);
    }

    await axios.post(endpoint, subscription.toJSON());
    console.log('Ready!');
  } catch (err) {
    console.log('Error:', err.message);
  }
})();
