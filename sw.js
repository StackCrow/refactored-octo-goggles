var CACHE = 'pw-manager-v2';
var FILES = [
  './',
  './index.html',
  './css/style.css',
  './js/app.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

// 安装：缓存所有文件
self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(CACHE).then(function (cache) {
      return cache.addAll(FILES);
    })
  );
  self.skipWaiting();
});

// 激活：清理旧缓存
self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (k) { return k !== CACHE; })
          .map(function (k) { return caches.delete(k); })
      );
    })
  );
  self.clients.claim();
});

// 请求：优先用缓存，没缓存才联网
self.addEventListener('fetch', function (e) {
  e.respondWith(
    caches.match(e.request).then(function (cached) {
      return cached || fetch(e.request);
    })
  );
});
