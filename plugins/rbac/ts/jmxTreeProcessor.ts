namespace RBAC {

  type MBeans = { [name: string]: Jmx.Folder };
  type BulkRequest = { [name: string]: string[] };

  export class JmxTreeProcessor {

    constructor(
      private jolokia: Jolokia.IJolokia,
      private jolokiaStatus: JVM.JolokiaStatus,
      private rbacTasks: RBACTasks) {
    }

    process(tree: Jmx.Folder): void {
      log.debug("Processing tree", tree);
      this.rbacTasks.getACLMBean().then((aclMBean) => {
        const mbeans = this.flatten(tree);
        switch (this.jolokiaStatus.listMethod) {
          case JVM.JolokiaListMethod.LIST_OPTIMISED:
            log.debug("Process JMX tree: optimised list mode");
            if (this.hasDecoratedRBAC(mbeans)) {
              log.debug("JMX tree already decorated with RBAC");
              this.processWithRBAC(mbeans);
            } else {
              log.debug("JMX tree not decorated with RBAC, fetching RBAC info now");
              this.processGeneral(aclMBean, mbeans);
            }
            log.debug("Processed tree mbeans with RBAC", mbeans);
            break;
          case JVM.JolokiaListMethod.LIST_GENERAL:
          case JVM.JolokiaListMethod.LIST_CANT_DETERMINE:
          default:
            log.debug("Process JMX tree: general mode");
            this.processGeneral(aclMBean, mbeans);
            log.debug("Processed tree mbeans", mbeans);
            break;
        }
      });
    }

    private flatten(tree: Jmx.Folder): MBeans {
      const mbeans: MBeans = {};
      this.flattenFolder(mbeans, tree);
      return mbeans;
    }

    /**
     * Recursive method to flatten MBeans folder
     */
    private flattenFolder(mbeans: MBeans, folder: Jmx.Folder): void {
      if (!Core.isBlank(folder.objectName)) {
        mbeans[folder.objectName] = folder;
      }
      if (folder.isFolder()) {
        folder.children.forEach(child => this.flattenFolder(mbeans, child as Jmx.Folder));
      }
    }

    /**
     * Check if RBACDecorator has been applied to the MBean tree at server side.
     */
    private hasDecoratedRBAC(mbeans: MBeans): boolean {
      const node = _.find(mbeans,
        folder => !_.isEmpty(folder.mbean.op) && _.isEmpty(folder.mbean.opByString));
      return _.isNil(node);
    }

    private processWithRBAC(mbeans: MBeans): void {
      // we already have everything related to RBAC in place, except 'class' property
      _.forEach(mbeans, (node: Jmx.Folder, mbeanName: string) => {
        const mbean = node.mbean;
        const canInvoke = mbean && (_.isNil(mbean.canInvoke) || mbean.canInvoke);
        this.addCanInvokeToClass(node, canInvoke);
      });
    }

    private processGeneral(aclMBean: string, mbeans: MBeans): void {
      const requests: Jolokia.IRequest[] = [];
      const bulkRequest: BulkRequest = {};
      // register canInvoke requests for each MBean and accumulate bulkRequest for all ops
      _.forEach(mbeans, (folder, mbeanName) => {
        this.addCanInvokeRequests(aclMBean, mbeanName, folder, requests, bulkRequest);
      });
      // register the bulk request finally based on the accumulated bulkRequest
      requests.push({
        type: 'exec',
        mbean: aclMBean,
        operation: 'canInvoke(java.util.Map)',
        arguments: [bulkRequest]
      });
      this.sendBatchRequest(mbeans, requests);
    }

    private addCanInvokeRequests(aclMBean: string, mbeanName: string, folder: Jmx.Folder,
      requests: Jolokia.IRequest[], bulkRequest: BulkRequest): void {
      // request for MBean
      requests.push({
        type: 'exec',
        mbean: aclMBean,
        operation: 'canInvoke(java.lang.String)',
        arguments: [mbeanName]
      });
      // bulk request for MBean ops
      if (folder.mbean && folder.mbean.op) {
        folder.mbean.opByString = {};
        const opList: string[] = [];
        _.forEach(folder.mbean.op, (op: Core.JMXOperation, opName: string) => {
          if (_.isArray(op)) {
            // overloaded ops
            _.forEach(op, (op) => this.addOperation(folder, opList, opName, op));
          } else {
            // single op
            this.addOperation(folder, opList, opName, op);
          }
        });
        if (!_.isEmpty(opList)) {
          bulkRequest[mbeanName] = opList;
        }
      }
    }

    private addOperation(folder: Jmx.Folder, opList: string[], opName: string, op: Core.JMXOperation): void {
      const operationString = Core.operationToString(opName, op.args);
      // enrich the mbean by indexing the full operation string so we can easily look it up later
      folder.mbean.opByString[operationString] = op;
      opList.push(operationString);
    }

    private sendBatchRequest(mbeans: MBeans, requests: Jolokia.IRequest[]): void {
      this.jolokia.request(requests, Core.onSuccess(
        (response) => {
          let mbean = response.request.arguments[0];
          if (mbean && _.isString(mbean)) {
            let canInvoke = response.value;
            mbeans[mbean]['canInvoke'] = response.value;
            this.addCanInvokeToClass(mbeans[mbean], canInvoke);
          } else {
            let responseMap = response.value;
            _.forEach(responseMap, (operations, mbeanName) => {
              _.forEach(operations, (data, operationName) => {
                mbeans[mbeanName].mbean.opByString[operationName]['canInvoke'] = data['CanInvoke'];
              });
            });
          }
        },
        { error: (response) => { } }));
    }

    private addCanInvokeToClass(mbean: any, canInvoke: boolean): void {
      let toAdd = canInvoke ? "can-invoke" : "cant-invoke";
      mbean['class'] = this.stripClasses(mbean['class']);
      mbean['class'] = this.addClass(mbean['class'], toAdd);
      if (!canInvoke) {
        // change the tree node icon to lock here
        mbean.icon = 'fa fa-lock';
      }
    }

    private stripClasses(css: string): string {
      if (Core.isBlank(css)) {
        return css;
      }
      let parts = css.split(" ");
      let answer = [];
      parts.forEach((part) => {
        if (part !== "can-invoke" && part !== "cant-invoke") {
          answer.push(part);
        }
      });
      return answer.join(" ").trim();
    }

    private addClass(css: string, _class: string): string {
      if (Core.isBlank(css)) {
        return _class;
      }
      let parts = css.split(" ");
      parts.push(_class);
      return _.uniq(parts).join(" ").trim();
    }

  }

}
