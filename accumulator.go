package main

import (
	"fmt"
	"crypto/sha256"
	"encoding/hex"
	// "encoding/json"
	"errors"

	"github.com/Nik-U/pbc"
	"github.com/athanorlabs/go-dleq/types"
	ring "github.com/neucc1997/ring-go"
)

// func addElement(x, i *pbc.Element, p *pbc.Pairing) *pbc.Element {
// 	g := p.NewG1()
// 	return g.PowZn(x, i)
// }

type Accumulator struct {
	value *pbc.Element // Accumulator value
}

type Witness struct {
	value *pbc.Element // Witness value
	acc   Accumulator // Accumulator value for current Witness
}

func (acc *Accumulator) IsEmpty(g *pbc.Element) bool {
	return g == acc. value
}

func (acc *Accumulator) IsEqual(acc2 *Accumulator) bool {
	return acc.value == acc2. value
}

// Update an accumulator
// acc: accumulator
// e_add: new element
// key: accumulator key
func (acc *Accumulator) AddElementWithKey(e_add, key *pbc.Element, pairing *pbc.Pairing) *Accumulator {
	acc.value.PowZn(acc.value, pairing.NewZr().Add(e_add, key))
	return acc
}

// Update a witness (Based on old accumulator)
// wt: witness
// acc_old: old accumulator
// e_add: new element
// e_self: self element
func (wt *Witness) AddElementForWitness(e_add, e_self *pbc.Element, pairing *pbc.Pairing) *Witness {
	wt.value.PowZn(wt.value, pairing.NewZr().Sub(e_add, e_self)).Add(wt.value, wt.acc.value)
	return wt
}

// Update an accumulator
// acc: accumulator
// e_delete: element to be deleted
// key: accumulator key
func (acc *Accumulator) DeleteElementWithKey(e_delete, key *pbc.Element, pairing *pbc.Pairing) *Accumulator {
	index := pairing.NewZr().Add(e_delete, key)
	index2 := pairing.NewZr().Invert(index)
	acc.value.PowZn(acc.value, index2)
	return acc
}

// Update a witness (Based on new accumulator)
// wt: witness
// acc: new accumulator
// e_delete: element to be deleted
// e_self: self element
func (wt *Witness) DeleteElementForWitness(e_delete, e_self *pbc.Element, acc *Accumulator, pairing *pbc.Pairing) *Witness {
	index := pairing.NewG1().Sub(wt.value, acc.value)
	index2 := pairing.NewZr().Sub(e_delete, e_self)
	index3 := pairing.NewZr().Invert(index2)
	wt.value.PowZn(index, index3)
	return wt
}

// e(Wit,h^e * h^p) = e(Acc,h)
func VerifyWitness(wit *Witness, acc *Accumulator, h, pk2, u_priv *pbc.Element, pairing *pbc.Pairing) bool {
	temp1 := pairing.NewGT().Pair(wit.value, pairing.NewG2().Add(pk2, pairing.NewG2().PowZn(h, u_priv)))
	temp2 := pairing.NewGT().Pair(acc.value, h)
	if temp1.Equals(temp2) {
		return true
	} else {
		return false
	}
}

// Get a witness with the help of the manager key
func (acc *Accumulator)EasyWayToGetWitness(u_priv, key *pbc.Element, pairing *pbc.Pairing) *Witness {
	var Wit Witness
	index := pairing.NewZr().Add(u_priv, key)
	index2 := pairing.NewZr().Invert(index)
	Wit.value = pairing.NewG1().SetBytes(acc.value.Bytes()).PowZn(acc.value, index2)
	Wit.acc.value = pairing.NewG1().SetBytes(acc.value.Bytes())
	return &Wit
}

type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

// AccumulatorContent implements the Content interface provided by merkletree and represents the content stored in the tree.
// pbk: public key string encoded in hex
// attr: 属性 string 先经过 hash 映射，然后转为 hex 编码的 string
// role: role information
type AccumulatorContent struct {
	PublicKey  string `json:"publicKey"`
	Attributes string `json:"attributes"`
	Role       string `json:"role"`
}

// CalculateHash hashes the values of a AccumulatorContent
func (t AccumulatorContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(append([]byte(t.PublicKey), []byte(t.Attributes)...)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents
func (t AccumulatorContent) Equals(other Content) (bool, error) {
	otherTC, ok := other.(AccumulatorContent)
	if !ok {
		return false, errors.New("value is not of type AccumulatorContent")
	}
	return t.PublicKey == otherTC.PublicKey && t.Attributes == otherTC.Attributes && t.Role == otherTC.Role, nil
}


// pairing test
func Test1() {
	// In a real application, generate this once and publish it
	params := pbc.GenerateA(160, 512)

	pairing := params.NewPairing()

	// Initialize group elements. pbc automatically handles garbage collection.
	g := pairing.NewG1()
	h := pairing.NewG2()
	x := pairing.NewGT()

	// Generate random group elements and pair them
	g.Rand()
	h.Rand()
	fmt.Printf("g = %s\n", g)
	fmt.Printf("h = %s\n", h)
	x.Pair(g, h)
	fmt.Printf("e(g,h) = %s\n", x)

	fmt.Printf("================\n")

	xt := pairing.NewG1()
	privKey := pairing.NewZr().Rand()
	xt.PowZn(g,privKey)

	// gt := pairing.NewG1().Rand()

	temp1 := pairing.NewGT().Pair(h, xt)
	temp2 := pairing.NewGT().Pair(h, g)
	temp2.PowZn(temp2, privKey)

	if !temp1.Equals(temp2) {
		fmt.Println("*BUG* Pairing check failed *BUG*")
	} else {
		fmt.Println("Pairing verified correctly")
	}
}

// Membership proof
func Test2() {
	// In a real application, generate this once and publish it
	params := pbc.GenerateA(160, 512)

	pairing := params.NewPairing()

	// Initialize group elements. pbc automatically handles garbage collection.
	g := pairing.NewG1().Rand()
	h := pairing.NewG2().Rand()

	privKey := pairing.NewZr().Rand()
	pubKey_1 := pairing.NewG1().PowZn(g, privKey)
	pubKey_2 := pairing.NewG2().PowZn(h, privKey)

	var Acc Accumulator
	Acc.value = pairing.NewG1().SetBytes(pubKey_1.Bytes())
	
	for i := 0; i < 9; i++ {
		Acc.AddElementWithKey(pairing.NewZr().Rand(), privKey, pairing)
	}

	u_priv := pairing.NewZr().Rand()
	var Wit Witness
	Wit.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	Acc.AddElementWithKey(u_priv, privKey, pairing)

	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())
	// Wit.acc = Accumulator{value: pairing.NewG1().SetBytes(Acc.value.Bytes())}

	if pairing.NewG2().Add(pubKey_2, pairing.NewG2().PowZn(h, u_priv)).Equals(pairing.NewG2().PowZn(h, pairing.NewZr().Add(privKey, u_priv))) {
		fmt.Println("succ1")
	}

	if pairing.NewG1().PowZn(Wit.value, pairing.NewZr().Add(privKey, u_priv)).Equals(Acc.value) {
		fmt.Println("succ2")
	}

	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Witness verified correctly")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}

}

// Add/delete members
func Test3() {
	// In a real application, generate this once and publish it
	params := pbc.GenerateA(160, 512)

	pairing := params.NewPairing()

	// Initialize group elements. pbc automatically handles garbage collection.
	g := pairing.NewG1().Rand()
	h := pairing.NewG2().Rand()

	var Acc Accumulator

	privKey := pairing.NewZr().Rand()
	pubKey_1 := pairing.NewG1().PowZn(g, privKey)
	pubKey_2 := pairing.NewG2().PowZn(h, privKey)

	Acc.value = pairing.NewG1().SetBytes(pubKey_1.Bytes())
	
	deleteEle := pairing.NewZr().Rand()
	Acc.AddElementWithKey(deleteEle, privKey, pairing)

	for i := 0; i < 9; i++ {
		Acc.AddElementWithKey(pairing.NewZr().Rand(), privKey, pairing)
	}

	u_priv := pairing.NewZr().Rand()
	var Wit Witness
	Wit.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	Acc.AddElementWithKey(u_priv, privKey, pairing)

	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Init witness verified correctly")
	} else {
		fmt.Println("  *BUG* Init witness check failed *BUG*")
	}

	// Delete Element
	Acc.DeleteElementWithKey(deleteEle, privKey, pairing)
	Wit.DeleteElementForWitness(deleteEle, u_priv, &Acc, pairing)
	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Witness verified correctly")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}

	// Add element
	newEle := pairing.NewZr().Rand()

	Acc.AddElementWithKey(newEle, privKey, pairing)
	Wit.AddElementForWitness(newEle, u_priv, pairing)
	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Witness verified correctly")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}

	// fmt.Println("invert test start")

	// sb1 := pairing.NewZr().Sub(deleteEle, u_priv)
	// g1_sb1 := pairing.NewG1().SetBytes(g.Bytes())
	// g1_sb1.PowZn(g1_sb1, sb1)

	// g2_isb1 := pairing.NewG2().SetBytes(h.Bytes())
	// g2_isb1.PowZn(g2_isb1, pairing.NewZr().Invert(sb1))

	// temp1 := pairing.NewGT().Pair(g1_sb1, g2_isb1)
	// temp2 := pairing.NewGT().Pair(g, h)
	// if temp1.Equals(temp2) {
	// 	fmt.Println("  Invert verified correctly")
	// } else {
	// 	fmt.Println("  *BUG* Invert check failed *BUG*")
	// }

	// fmt.Println("invert test end")
}

// 成员证明 —— Hash 版本
func Test4() {
	// In a real application, generate this once and publish it
	params := pbc.GenerateA(160, 512)

	pairing := params.NewPairing()

	// Initialize group elements. pbc automatically handles garbage collection.
	g := pairing.NewG1().Rand()
	h := pairing.NewG2().Rand()

	var Acc Accumulator

	privKey := pairing.NewZr().Rand()
	pubKey_1 := pairing.NewG1().PowZn(g, privKey)
	pubKey_2 := pairing.NewG2().PowZn(h, privKey)

	Acc.value = pairing.NewG1().SetBytes(pubKey_1.Bytes())
	
	// Generate key pairs
	const size = 10
	curve := ring.Secp256k1()
	pris := make([]types.Scalar, size)
	pubs := make([]types.Point, size)
	for i := 0; i < size; i++ {
		priv := curve.NewRandomScalar()
		// fmt.Printf("Size of priv: %d bytes\n", int64(reflect.TypeOf(priv).Size()))
		pris[i] = priv
		pubs[i] = curve.ScalarBaseMul(priv)
	}

	var list []Content
	for i := 0; i < size; i++ {
		var a_hash = sha256.Sum256([]byte("Test Attribute"))
		list = append(list, AccumulatorContent{PublicKey: hex.EncodeToString(pubs[i].Encode()), Attributes: hex.EncodeToString(a_hash[:]), Role: "Test Role"})
	}

	for i := 0; i < size-1; i++ {
		hash, _ := list[i].CalculateHash()
		Acc.AddElementWithKey(pairing.NewZr().SetBytes(hash), privKey, pairing)
	}

	hash, _ := list[9].CalculateHash()
	u_priv := pairing.NewZr().SetBytes(hash)
	var Wit Witness
	Wit.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	Acc.AddElementWithKey(u_priv, privKey, pairing)

	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Witness verified correctly")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}
}

func Demo() {

	fmt.Println("0.Initialize system parameters")

	// ecc -- 用于生成用户公私钥
	curve := ring.Secp256k1()

	// pairing -- 用于维护累加器
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
	
	g := pairing.NewG1().Rand()
	h := pairing.NewG2().Rand()

	sharedParams := params.String() 	
	sharedG := g.Bytes()
	sharedH := h.Bytes()

	fmt.Println("pairing parameters:", sharedParams)
	fmt.Println("generator g:", hex.EncodeToString(sharedG))
	fmt.Println("generator h:", hex.EncodeToString(sharedH))
	fmt.Println()



	fmt.Println("1.Initialize accumulator")

	// initialize manager public-private key pair
	privKey := pairing.NewZr().Rand()
	pubKey_1 := pairing.NewG1().PowZn(g, privKey)
	pubKey_2 := pairing.NewG2().PowZn(h, privKey)

	var Acc Accumulator
	Acc.value = pairing.NewG1().SetBytes(pubKey_1.Bytes())

	fmt.Println("first accumulator:", hex.EncodeToString(pubKey_1.Bytes()))
	fmt.Println("pk2 of the accumulator:", hex.EncodeToString(pubKey_2.Bytes()))
	fmt.Println()


	fmt.Println("2.Initialize 10 users and add them into the accumulator")

	const size = 10

	// initialize user public-private key pair
	pris := make([]types.Scalar, size)
	pubs := make([]types.Point, size)
	for i := 0; i < size; i++ {
		priv := curve.NewRandomScalar()
		// fmt.Printf("Size of priv: %d bytes\n", int64(reflect.TypeOf(priv).Size()))
		pris[i] = priv
		pubs[i] = curve.ScalarBaseMul(priv)
	}

	// initialize user content
	var list []Content
	for i := 0; i < size; i++ {
		list = append(list, AccumulatorContent{PublicKey: hex.EncodeToString(pubs[i].Encode()), Attributes: "Test Attributes", Role: "Test Role"})
	}

	// accumulate the content of tht first size-1 user to the accumulator
	for i := 0; i < size-1; i++ {
		hash, _ := list[i].CalculateHash()
		index := pairing.NewZr().SetBytes(hash)
		fmt.Println("element to be added to acc:", hex.EncodeToString(hash[:]))
		Acc.AddElementWithKey(index, privKey, pairing)
	}

	// generate the witness for the last user, then update the accumulator
	hash, _ := list[size-1].CalculateHash()
	fmt.Println("element to be added to acc:", hex.EncodeToString(hash[:]))

	u_priv := pairing.NewZr().SetBytes(hash)
	var Wit Witness
	Wit.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	Acc.AddElementWithKey(u_priv, privKey, pairing)

	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	fmt.Println("membership proof:", hex.EncodeToString(Wit.value.Bytes()))
	fmt.Println("accumulator:", hex.EncodeToString(Acc.value.Bytes()))
	fmt.Println()

	fmt.Println("3.Verify the user info with accumulator")

	// temp1 := pairing.NewGT().Pair(Wit.value, pairing.NewG2().Add(pubKey_2, pairing.NewG2().PowZn(h, u_priv)))
	// temp2 := pairing.NewGT().Pair(Acc.value, h)
	fmt.Println("accumulator:", hex.EncodeToString(Acc.value.Bytes()))
	fmt.Println("pk2 of the accumulator:", hex.EncodeToString(pubKey_2.Bytes()))
	fmt.Println("witness", hex.EncodeToString(Wit.value.Bytes()))
	fmt.Println("user info", hex.EncodeToString(u_priv.Bytes()))
	fmt.Println("generator h:", hex.EncodeToString(h.Bytes()))
	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Witness verified correctly")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}
	fmt.Println()

	fmt.Println("4.Add two users")

	// info of the first new user
	new_priv_1 := curve.NewRandomScalar()
	new_pub_1  := curve.ScalarBaseMul(new_priv_1)
	new_accC_1 := AccumulatorContent{PublicKey: hex.EncodeToString(new_pub_1.Encode()), Attributes: "Test Attributes", Role: "Test Role"}

	hash, _ = new_accC_1.CalculateHash()
	new_u_priv_1 := pairing.NewZr().SetBytes(hash)
	fmt.Println("user info 1", hex.EncodeToString(new_u_priv_1.Bytes()))

	// info for the second new user
	new_priv_2 := curve.NewRandomScalar()
	new_pub_2  := curve.ScalarBaseMul(new_priv_2)
	new_accC_2 := AccumulatorContent{PublicKey: hex.EncodeToString(new_pub_2.Encode()), Attributes: "Test Attributes", Role: "Test Role"}

	hash, _ = new_accC_2.CalculateHash()
	new_u_priv_2 := pairing.NewZr().SetBytes(hash)
	fmt.Println("user info 2:", hex.EncodeToString(new_u_priv_2.Bytes()))

	// add the info of the two new users to accumulator
	// add user 1
	Acc.AddElementWithKey(new_u_priv_1, privKey, pairing)
	// buckup acc
	Acc_add_1 := pairing.NewG1().SetBytes(Acc.value.Bytes())
	fmt.Println("acc_new (after adding user 1):", hex.EncodeToString(Acc_add_1.Bytes()))

	// add user 2
	Acc.AddElementWithKey(new_u_priv_2, privKey, pairing)
	fmt.Println("acc_new (after adding user 2):", hex.EncodeToString(Acc.value.Bytes()))

	// update user witness：user acc_old and info of new user
	// update witness with the info of new user 1
	Wit.AddElementForWitness(new_u_priv_1, u_priv, pairing)
	Wit.acc.value = pairing.NewG1().SetBytes(Acc_add_1.Bytes())
	fmt.Println("Member proof information after adding new user 1:", hex.EncodeToString(Wit.acc.value.Bytes()))

	// Update Witness based on user 2's information
	Wit.AddElementForWitness(new_u_priv_2, u_priv, pairing) 	
	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())
	fmt.Println("Member proof information after adding new user 2:", hex.EncodeToString(Wit.acc.value.Bytes()))

	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Witness verified correctly (after adding new user)")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}
	fmt.Println()


	fmt.Println("5. Delete 2 users (user 4 and user 6)")

	// Remove the 4th user
	delete_ele_4 := list[4-1]
	hash, _ = delete_ele_4.CalculateHash()
	delete_u_priv_4 := pairing.NewZr().SetBytes(hash)
	fmt.Println("Information of user 4 to be deleted:", hex.EncodeToString(delete_u_priv_4.Bytes()))

	// Remove the 6th user
	delete_ele_6 := list[6-1]
	hash, _ = delete_ele_6.CalculateHash()
	delete_u_priv_6 := pairing.NewZr().SetBytes(hash)
	fmt.Println("Information of user 6 to be deleted:", hex.EncodeToString(delete_u_priv_6.Bytes()))

	// Delete user information from Acc
	Acc.DeleteElementWithKey(delete_u_priv_4, privKey, pairing)
	var Acc_del_4 Accumulator
	Acc_del_4.value = pairing.NewG1().SetBytes(Acc.value.Bytes())
	fmt.Println("Acc information after deleting user 4:", hex.EncodeToString(Acc_del_4.value.Bytes()))

	Acc.DeleteElementWithKey(delete_u_priv_6, privKey, pairing)
	fmt.Println("Acc information after deleting user 6:", hex.EncodeToString(Acc.value.Bytes()))	

	// Update Witness: Use the new Acc and deleted user information
	Wit.DeleteElementForWitness(delete_u_priv_4, u_priv, &Acc_del_4, pairing)
	Wit.acc.value = pairing.NewG1().SetBytes(Acc_del_4.value.Bytes())
	fmt.Println("Member proof information after deleting user 4:", hex.EncodeToString(Wit.acc.value.Bytes()))

	Wit.DeleteElementForWitness(delete_u_priv_6, u_priv, &Acc, pairing) 	
	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())
	fmt.Println("Member proof information after deleting user 6:", hex.EncodeToString(Wit.acc.value.Bytes()))

	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Witness verified correctly (after deleting old user)")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}
}

func HelperTest() {

	fmt.Println("0. Initialize system parameters")

	// ecc -- Used to generate user public/private keys
	curve := ring.Secp256k1()

	// pairing -- Used to maintain the accumulator
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()

	g := pairing.NewG1().Rand()
	h := pairing.NewG2().Rand()

	sharedParams := params.String()
	sharedG := g.Bytes()
	sharedH := h.Bytes()

	fmt.Println("Pairing parameters:", sharedParams)
	fmt.Println("g parameter:", hex.EncodeToString(sharedG))
	fmt.Println("h parameter:", hex.EncodeToString(sharedH))
	fmt.Println()



	fmt.Println("1. Initialize the accumulator")

	// Administrator's public/private keys
	privKey := pairing.NewZr().Rand()
	pubKey_1 := pairing.NewG1().PowZn(g, privKey)
	pubKey_2 := pairing.NewG2().PowZn(h, privKey)

	var Acc Accumulator
	Acc.value = pairing.NewG1().SetBytes(pubKey_1.Bytes())

	fmt.Println("Initial accumulator:", hex.EncodeToString(pubKey_1.Bytes()))
	fmt.Println("Accumulator pk2:", hex.EncodeToString(pubKey_2.Bytes()))
	fmt.Println()


	fmt.Println("2. Initialize user information (10 users) and add to the accumulator")

	const size = 10

	// Initialize user public/private keys
	pris := make([]types.Scalar, size)
	pubs := make([]types.Point, size)
	for i := 0; i < size; i++ {
		priv := curve.NewRandomScalar()
		// fmt.Printf("Size of priv: %d bytes\n", int64(reflect.TypeOf(priv).Size()))
		pris[i] = priv
		pubs[i] = curve.ScalarBaseMul(priv)
	}

	// Initialize user content
	var list []Content
	for i := 0; i < size; i++ {
		var a_hash = sha256.Sum256([]byte("Test Attribute"))
		list = append(list, AccumulatorContent{PublicKey: hex.EncodeToString(pubs[i].Encode()), Attributes: hex.EncodeToString(a_hash[:]), Role: "Test Role"})
	}

	// Add the first (size-1) user contents to the accumulator
	for i := 0; i < size-1; i++ {
		hash, _ := list[i].CalculateHash()
		index := pairing.NewZr().SetBytes(hash)
		fmt.Println("Element to be added to the accumulator:", hex.EncodeToString(index.Bytes()))
		Acc.AddElementWithKey(index, privKey, pairing)
	}

	// Generate Witness for the last user's content and update the Accumulator
	hash, _ := list[size-1].CalculateHash()
	fmt.Println("Element to be added to the accumulator (current user):", hex.EncodeToString(hash[:]))

	u_priv := pairing.NewZr().SetBytes(hash)
	var Wit Witness
	Wit.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	Acc.AddElementWithKey(u_priv, privKey, pairing)

	Wit.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())

	fmt.Println("Membership proof:", hex.EncodeToString(Wit.value.Bytes()))
	fmt.Println("Accumulator:", hex.EncodeToString(Acc.value.Bytes()))
	fmt.Println()

	fmt.Println("3. Verify user information using the accumulator")

	// temp1 := pairing.NewGT().Pair(Wit.value, pairing.NewG2().Add(pubKey_2, pairing.NewG2().PowZn(h, u_priv)))
	// temp2 := pairing.NewGT().Pair(Acc.value, h)
	fmt.Println("Accumulator:", hex.EncodeToString(Acc.value.Bytes()))
	fmt.Println("Accumulator pk2:", hex.EncodeToString(pubKey_2.Bytes()))
	fmt.Println("Membership proof:", hex.EncodeToString(Wit.value.Bytes()))
	fmt.Println("User information:", hex.EncodeToString(u_priv.Bytes()))
	fmt.Println("h:", hex.EncodeToString(h.Bytes()))
	if VerifyWitness(&Wit, &Acc, h, pubKey_2, u_priv, pairing) {
		fmt.Println("  Witness verified correctly")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}
	fmt.Println()

	fmt.Println("4. User directly obtains the witness under the current accumulator from the administrator")

	// Obtain information of the 5th user
	hash, _ = list[5].CalculateHash()
	u_priv_5 := pairing.NewZr().SetBytes(hash)

	Wit5 := new(Witness)
	Wit5 = Acc.EasyWayToGetWitness(u_priv_5, privKey, pairing)
	if VerifyWitness(Wit5, &Acc, h, pubKey_2, u_priv_5, pairing) {
		fmt.Println("  Witness verified correctly")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}
	fmt.Println()

	fmt.Println("5. Add user")

	// New user information
	new_priv_1 := curve.NewRandomScalar()
	new_pub_1  := curve.ScalarBaseMul(new_priv_1)
	var a_hash = sha256.Sum256([]byte("Test Attribute"))
	new_accC_1 := AccumulatorContent{PublicKey: hex.EncodeToString(new_pub_1.Encode()), Attributes: hex.EncodeToString(a_hash[:]), Role: "Test Role"}

	hash, _ = new_accC_1.CalculateHash()
	new_u_priv_1 := pairing.NewZr().SetBytes(hash)
	fmt.Println("New user 1 information:", hex.EncodeToString(new_u_priv_1.Bytes()))

	// Add new user 1
	Acc.AddElementWithKey(new_u_priv_1, privKey, pairing)
	fmt.Println("Accumulator information after adding new user 1:", hex.EncodeToString(Acc.value.Bytes()))

	// Update the 5th user's Witness based on new user 1's information
	Wit5.AddElementForWitness(new_u_priv_1, u_priv_5, pairing)
	Wit5.acc.value = pairing.NewG1().SetBytes(Acc.value.Bytes())
	fmt.Println("Membership proof information after adding new user 1:", hex.EncodeToString(Wit5.value.Bytes()))

	if VerifyWitness(Wit5, &Acc, h, pubKey_2, u_priv_5, pairing) {
		fmt.Println("  Witness verified correctly (after adding new user)")
	} else {
		fmt.Println("  *BUG* Witness check failed *BUG*")
	}
	fmt.Println()
	
}


// func main() {
	
// 	// test1()
// 	// test2()
// 	// test3()
// 	// test4()
// 	demo()
// 	fmt.Println("=================================================")
// 	helperTest()
// } 

