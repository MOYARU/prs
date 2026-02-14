pkgname=prs-scan
pkgver=1.8.0
pkgrel=1
pkgdesc="Defensive-first web security scanner"
arch=('x86_64' 'aarch64')
url="https://github.com/MOYARU/prs"
license=('MIT')
depends=()
makedepends=('go' 'git')
source=("git+${url}.git#tag=v${pkgver}")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname"
  go build -trimpath -ldflags "-s -w" -o prs ./main.go
}

package() {
  cd "$srcdir/$pkgname"
  install -Dm755 prs "$pkgdir/usr/bin/prs"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
