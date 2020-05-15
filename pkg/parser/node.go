package parser

import (
	"fmt"
	"net"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

type Node struct {
	FormatVersion string `yaml:"format"`
	//Enable config + runtime debug of node via config o/
	Debug bool `yaml:"debug,omitempty"`
	//If enabled, the node (and its child) will report their own statistics
	Profiling bool `yaml:"profiling,omitempty"`
	//Name, author, description and reference(s) for parser pattern
	Name        string   `yaml:"name,omitempty"`
	Author      string   `yaml:"author,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Rerferences []string `yaml:"references,omitempty"`
	//if debug is present in the node, keep its specific logger in runtime structure
	logger *log.Entry `yaml:"-"`
	//This is mostly a hack to make writting less repetive.
	//relying on stage, we know which field to parse, and we
	//can as well promote log to next stage on success
	Stage string `yaml:"stage,omitempty"`
	//OnSuccess allows to tag a node to be able to move log to next stage on success
	OnSuccess string `yaml:"onsuccess,omitempty"`
	rn        string //this is only for us in debug, a random generated name for each node
	//Filter is executed at runtime (with current log line as context)
	//and must succeed or node is exited
	Filter        string      `yaml:"filter,omitempty"`
	RunTimeFilter *vm.Program `yaml:"-" json:"-"` //the actual compiled filter

	//If node has leafs, execute all of them until one asks for a 'break'
	SuccessNodes []Node `yaml:"nodes,omitempty"`
	//Flag used to describe when to 'break' or return an 'error'
	// BreakBehaviour string `yaml:"break,omitempty"`
	// Error          string `yaml:"error,omitempty"`

	/* If the node is actually a leaf, it can have : grok, enrich, statics */
	//pattern_syntax are named grok patterns that are re-utilised over several grok patterns
	SubGroks map[string]string `yaml:"pattern_syntax,omitempty"`
	//Holds a grok pattern
	Grok types.GrokPattern `yaml:"grok,omitempty"`
	//Statics can be present in any type of node and is executed last
	Statics []types.ExtraField `yaml:"statics,omitempty"`
	//Whitelists
	Whitelist types.Whitelist `yaml:"whitelist,omitempty"`
}

func (n *Node) validate(pctx *UnixParserCtx) error {

	//stage is being set automagically
	if n.Stage == "" {
		return fmt.Errorf("Stage needs to be an existing stage")
	}

	/* "" behaves like continue */
	if n.OnSuccess != "continue" && n.OnSuccess != "next_stage" && n.OnSuccess != "" {
		return fmt.Errorf("onsuccess '%s' not continue,next_stage", n.OnSuccess)
	}
	if n.Filter != "" && n.RunTimeFilter == nil {
		return fmt.Errorf("non-empty filter '%s' was not compiled", n.Filter)
	}

	if n.Grok.RunTimeRegexp != nil || n.Grok.TargetField != "" {
		if n.Grok.TargetField == "" {
			return fmt.Errorf("grok's apply_on can't be empty")
		}
		if n.Grok.RegexpName == "" && n.Grok.RegexpValue == "" {
			return fmt.Errorf("grok needs 'pattern' or 'name'")
		}
	}

	for idx, static := range n.Statics {
		if static.Method != "" {
			if static.ExpValue == "" {
				return fmt.Errorf("static %d : when method is set, expression must be present", idx)
			}
			method_found := false
			for _, enricherCtx := range ECTX {
				if _, ok := enricherCtx.Funcs[static.Method]; ok {
					method_found = true
					break
				}
			}
			if method_found == false {
				return fmt.Errorf("the method '%s' doesn't exist", static.Method)
			}
		} else {
			if static.Meta == "" && static.Parsed == "" && static.TargetByName == "" {
				return fmt.Errorf("static %d : at least one of meta/event/target must be set", idx)
			}
			if static.Value == "" && static.RunTimeValue == nil {
				return fmt.Errorf("static %d value or expression must be set", idx)
			}
		}
	}
	return nil
}

func (n *Node) process(p *types.Event, ctx UnixParserCtx) (bool, error) {
	var NodeState bool = true
	clog := n.logger

	clog.Debugf("Event entering node")
	if n.RunTimeFilter != nil {
		//Evaluate node's filter
		output, err := expr.Run(n.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": p}))
		if err != nil {
			clog.Warningf("failed to run filter : %v", err)
			clog.Debugf("Event leaving node : ko")
			return false, nil
		}
		switch output.(type) {
		case bool:
			/* filter returned false, don't process Node */
			if output.(bool) == false {
				NodeState = false
				clog.Debugf("eval(FALSE) '%s'", n.Filter)
				clog.Debugf("Event leaving node : ko")
				return false, nil
			}
		default:
			clog.Warningf("Expr '%s' returned non-bool, abort : %T", n.Filter, output)
			clog.Debugf("Event leaving node : ko")
			NodeState = false
			return false, nil
		}
		NodeState = true
		clog.Debugf("eval(TRUE) '%s'", n.Filter)
	} else {
		clog.Tracef("Node has not filter, enter")
		NodeState = true
	}

	if n.Profiling == true && n.Name != "" {
		NodesHits.With(prometheus.Labels{"source": p.Line.Src, "name": n.Name}).Inc()
	}
	set := false
	var src net.IP
	/*overflow and log don't hold the source ip in the same field, should be changed */
	/* perform whitelist checks for ips, cidr accordingly */
	if p.Type == types.LOG {
		if _, ok := p.Meta["source_ip"]; ok {
			src = net.ParseIP(p.Meta["source_ip"])
		}
	} else if p.Type == types.OVFLW {
		src = net.ParseIP(p.Overflow.Source_ip)
	}
	if src != nil {
		for _, v := range n.Whitelist.B_Ips {
			if v.Equal(src) {
				clog.Infof("Event from [%s] is whitelisted by Ips !", src)
				p.Whitelisted = true
				set = true
			}
		}

		for _, v := range n.Whitelist.B_Cidrs {
			if v.Contains(src) {
				clog.Debugf("Event from [%s] is whitelisted by Cidrs !", src)
				p.Whitelisted = true
				set = true
			} else {
				clog.Debugf("whitelist: %s not in [%s]", src, v)
			}
		}
	} else {
		clog.Debugf("no ip in event, cidr/ip whitelists not checked")
	}
	/* run whitelist expression tests anyway */
	for _, e := range n.Whitelist.B_Exprs {
		output, err := expr.Run(e, exprhelpers.GetExprEnv(map[string]interface{}{"evt": p}))
		if err != nil {
			clog.Warningf("failed to run whitelist expr : %v", err)
			clog.Debugf("Event leaving node : ko")
			return false, nil
		}
		switch output.(type) {
		case bool:
			/* filter returned false, don't process Node */
			if output.(bool) == true {
				clog.Infof("Event is whitelisted by Expr !")
				p.Whitelisted = true
				set = true
			}
		}
	}
	if set == true {
		p.WhiteListReason = n.Whitelist.Reason
		/*huglily wipe the ban order if the event is whitelisted and it's an overflow */
		if p.Type == types.OVFLW { /*don't do this at home kids */
			//			p.Overflow.OverflowAction = ""
			//Break this for now. Souldn't have been done this way, but that's not taht serious
			/*only display logs when we discard ban to avoid spam*/
			clog.Infof("Ban for %s whitelisted, reason [%s]", p.Overflow.Source.Ip.String(), n.Whitelist.Reason)
		}
	}

	//Iterate on leafs
	if len(n.SuccessNodes) > 0 {
		for _, leaf := range n.SuccessNodes {
			//clog.Debugf("Processing sub-node %d/%d : %s", idx, len(n.SuccessNodes), leaf.rn)
			ret, err := leaf.process(p, ctx)
			if err != nil {
				clog.Tracef("\tNode (%s) failed : %v", leaf.rn, err)
				clog.Debugf("Event leaving node : ko")
				return false, err
			}
			clog.Tracef("\tsub-node (%s) ret : %v (strategy:%s)", leaf.rn, ret, n.OnSuccess)
			if ret == true {
				NodeState = true
				/* if chil is successful, stop processing */
				if n.OnSuccess == "next_stage" {
					clog.Debugf("child is success, OnSuccess=next_stage, skip")
					break
				}
			} else {
				NodeState = false
			}
		}
	}
	/*todo : check if a node made the state change ?*/
	/* should the childs inherit the on_success behaviour */

	clog.Tracef("State after nodes : %v", NodeState)

	//Process grok if present, should be exclusive with nodes :)
	gstr := ""
	if n.Grok.RunTimeRegexp != nil {
		clog.Tracef("Processing grok pattern : %s : %p", n.Grok.RegexpName, n.Grok.RunTimeRegexp)
		//for unparsed, parsed etc. set sensible defaults to reduce user hassle
		if n.Grok.TargetField == "" {
			clog.Fatalf("not default field and no specified on stage '%s'", n.Stage)

		} else {
			//it's a hack to avoid using real reflect
			if n.Grok.TargetField == "Line.Raw" {
				gstr = p.Line.Raw
			} else if val, ok := p.Parsed[n.Grok.TargetField]; ok {
				gstr = val
			} else {
				clog.Debugf("(%s) target field '%s' doesn't exist in %v", n.rn, n.Grok.TargetField, p.Parsed)
				NodeState = false
				//return false, nil
			}
		}

		grok := n.Grok.RunTimeRegexp.Parse(gstr)
		if len(grok) > 0 {
			clog.Debugf("+ Grok '%s' returned %d entries to merge in Parsed", n.Grok.RegexpName, len(grok))
			//We managed to grok stuff, merged into parse
			for k, v := range grok {
				clog.Debugf("\t.Parsed['%s'] = '%s'", k, v)
				p.Parsed[k] = v
			}
			// if the grok succeed, process associated statics
			err := ProcessStatics(n.Grok.Statics, p, clog)
			if err != nil {
				clog.Fatalf("(%s) Failed to process statics : %v", n.rn, err)
			}
		} else {
			//grok failed, node failed
			clog.Debugf("+ Grok '%s' didn't return data on '%s'", n.Grok.RegexpName, gstr)
			//clog.Tracef("on '%s'", gstr)
			NodeState = false
		}

	} else {
		clog.Tracef("! No grok pattern : %p", n.Grok.RunTimeRegexp)
	}

	//grok or leafs failed, don't process statics
	if NodeState == false {
		if n.Profiling == true && n.Name != "" {
			NodesHitsKo.With(prometheus.Labels{"source": p.Line.Src, "name": n.Name}).Inc()
		}
		clog.Debugf("Event leaving node : ko")
		return NodeState, nil
	}

	if n.Profiling == true && n.Name != "" {
		NodesHitsOk.With(prometheus.Labels{"source": p.Line.Src, "name": n.Name}).Inc()
	}
	if len(n.Statics) > 0 {
		clog.Debugf("+ Processing %d statics", len(n.Statics))
		// if all else is good, process node's statics
		err := ProcessStatics(n.Statics, p, clog)
		if err != nil {
			clog.Fatalf("Failed to process statics : %v", err)
		}
	} else {
		clog.Tracef("! No node statics")
	}

	if NodeState == true {
		clog.Debugf("Event leaving node : ok")
		log.Tracef("node is successful, check strategy")
		if n.OnSuccess == "next_stage" {
			idx := stageidx(p.Stage, ctx.Stages)
			//we're at the last stage
			if idx+1 == len(ctx.Stages) {
				clog.Debugf("node reached the last stage : %s", p.Stage)
			} else {
				clog.Debugf("move Event from stage %s to %s", p.Stage, ctx.Stages[idx+1])
				p.Stage = ctx.Stages[idx+1]
			}
		} else {
			clog.Tracef("no strategy on success (%s), continue !", n.OnSuccess)
		}
	} else {
		clog.Debugf("Event leaving node : ko")
	}
	clog.Tracef("Node successful, continue")
	return NodeState, nil
}

func (n *Node) compile(pctx *UnixParserCtx) error {
	var err error
	var valid bool

	valid = false

	dumpr := spew.ConfigState{MaxDepth: 1, DisablePointerAddresses: true}
	n.rn = seed.Generate()

	log.Debugf("compile, node is %s", n.Stage)
	/* if the node has debugging enabled, create a specific logger with debug
	that will be used only for processing this node ;) */
	if n.Debug == true {
		var clog = logrus.New()
		clog.SetLevel(log.DebugLevel)
		n.logger = clog.WithFields(log.Fields{
			"id": n.rn,
		})
		n.logger.Infof("%s has debug enabled", n.Name)
	} else {
		/* else bind it to the default one (might find something more elegant here)*/
		n.logger = log.WithFields(log.Fields{
			"id": n.rn,
		})
	}

	/* display info about top-level nodes, they should be the only one with explicit stage name ?*/
	n.logger = n.logger.WithFields(log.Fields{"stage": n.Stage, "name": n.Name})

	n.logger.Tracef("Compiling : %s", dumpr.Sdump(n))

	//compile filter if present
	if n.Filter != "" {
		n.RunTimeFilter, err = expr.Compile(n.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			return fmt.Errorf("compilation of '%s' failed: %v", n.Filter, err)
		}
	}

	/* handle pattern_syntax and groks */
	for node, pattern := range n.SubGroks {
		n.logger.Debugf("Adding subpattern '%s' : '%s'", node, pattern)
		if err := pctx.Grok.Add(node, pattern); err != nil {
			n.logger.Errorf("Unable to compile subpattern %s : %v", node, err)
			return err
		}
	}
	/* load grok by name or compile in-place */
	if n.Grok.RegexpName != "" {
		n.logger.Debugf("+ Regexp Compilation '%s'", n.Grok.RegexpName)
		n.Grok.RunTimeRegexp, err = pctx.Grok.Get(n.Grok.RegexpName)
		if err != nil {
			n.logger.Fatalf("Unable to find grok '%s' : %v\n", n.Grok.RegexpName, err)
		}
		if n.Grok.RunTimeRegexp == nil {
			n.logger.Fatalf("Didn't find regexp : %s", n.Grok.RegexpName)
		}
		n.logger.Debugf("%s regexp: %s", n.Grok.RegexpName, n.Grok.RunTimeRegexp.Regexp.String())
		valid = true
	} else if n.Grok.RegexpValue != "" {
		//n.logger.Debugf("+ Regexp Compilation '%s'", n.Grok.RegexpValue)
		n.Grok.RunTimeRegexp, err = pctx.Grok.Compile(n.Grok.RegexpValue)
		if err != nil {
			n.logger.Fatalf("Failed to compile grok '%s': %v\n", n.Grok.RegexpValue, err)
		}
		if n.Grok.RunTimeRegexp == nil {
			// We shouldn't be here because compilation succeeded, so regexp shouldn't be nil
			n.logger.Fatalf("Grok compilation failure: %s", n.Grok.RegexpValue)
		}
		n.logger.Debugf("%s regexp : %s", n.Grok.RegexpValue, n.Grok.RunTimeRegexp.Regexp.String())
		valid = true
	}
	/* load grok statics */
	if len(n.Grok.Statics) > 0 {
		//compile expr statics if present
		for idx, _ := range n.Grok.Statics {
			if n.Grok.Statics[idx].ExpValue != "" {
				n.Grok.Statics[idx].RunTimeValue, err = expr.Compile(n.Grok.Statics[idx].ExpValue,
					expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
				if err != nil {
					return err
				}
			}
		}
		valid = true
	}
	/* compile leafs if present */
	if len(n.SuccessNodes) > 0 {
		for idx, _ := range n.SuccessNodes {
			/*propagate debug/stats to child nodes*/
			if n.SuccessNodes[idx].Debug == false && n.Debug == true {
				n.SuccessNodes[idx].Debug = true
			}
			if n.SuccessNodes[idx].Profiling == false && n.Profiling == true {
				n.SuccessNodes[idx].Profiling = true
			}
			n.SuccessNodes[idx].Stage = n.Stage
			err = n.SuccessNodes[idx].compile(pctx)
			if err != nil {
				return err
			} else {
				//n.logger.Debugf("Leaf compilation suceeded: %v\n", n.SuccessNodes[idx])
			}
			//set child node to parent stage
		}
		valid = true
	}
	/* load statics if present */
	for idx, _ := range n.Statics {
		if n.Statics[idx].ExpValue != "" {
			n.Statics[idx].RunTimeValue, err = expr.Compile(n.Statics[idx].ExpValue, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
			if err != nil {
				n.logger.Errorf("Statics Compilation failed %v.", err)
				return err
			}
		}
		valid = true
	}

	/* compile whitelists if present */
	for _, v := range n.Whitelist.Ips {
		n.Whitelist.B_Ips = append(n.Whitelist.B_Ips, net.ParseIP(v))
		n.logger.Debugf("adding ip %s to whitelists", net.ParseIP(v))
		valid = true
	}
	for _, v := range n.Whitelist.Cidrs {
		_, tnet, err := net.ParseCIDR(v)
		if err != nil {
			n.logger.Fatalf("Unable to parse cidr whitelist '%s' : %v.", v, err)
		}
		n.Whitelist.B_Cidrs = append(n.Whitelist.B_Cidrs, tnet)
		n.logger.Debugf("adding cidr %s to whitelists", tnet)
		valid = true
	}
	for _, v := range n.Whitelist.Exprs {
		expr, err := expr.Compile(v, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			n.logger.Fatalf("Unable to compile whitelist expression '%s' : %v.", v, err)
		}
		n.Whitelist.B_Exprs = append(n.Whitelist.B_Exprs, expr)
		n.logger.Debugf("adding expression %s to whitelists", v)
		valid = true
	}

	if valid == false {
		/* node is empty, error force return */
		n.logger.Infof("Node is empty: %s", spew.Sdump(n))
		n.Stage = ""
	}
	if err := n.validate(pctx); err != nil {
		return err
		//n.logger.Fatalf("Node is invalid : %s", err)
	}
	return nil
}
