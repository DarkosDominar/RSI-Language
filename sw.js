const CACHE_NAME = 'rsi-translator-v1';
const urlsToCache = [
  './',
  './index.html',
  './manifest.json',
  './js/tesseract.min.js',
  './js/FileSaver.min.js',
  './js/tesseract-worker.js',
  './js/tesseract-core.js',
  './js/tessdata/ara.traineddata'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
});