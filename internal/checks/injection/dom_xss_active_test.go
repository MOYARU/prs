package injection

import "testing"

func TestHasParamDOMFlow(t *testing.T) {
	body := `<html><script>
const v = new URLSearchParams(location.search).get("q");
document.getElementById("x").innerHTML = v;
</script></html>`
	ok, ev := hasParamDOMFlow(body, "q")
	if !ok {
		t.Fatal("expected DOM flow for parameter q")
	}
	if ev == "" {
		t.Fatal("expected evidence")
	}
}

func TestHasParamDOMFlow_NoSink(t *testing.T) {
	body := `<html><script>
const v = new URLSearchParams(location.search).get("q");
document.getElementById("x").textContent = v;
</script></html>`
	ok, _ := hasParamDOMFlow(body, "q")
	if ok {
		t.Fatal("did not expect DOM flow without risky sink")
	}
}
